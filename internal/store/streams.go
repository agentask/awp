// Package store: awp-streaming-v0.1.md §4/§6 chunk reassembly.
//
// Two buckets: `stream_meta` (one entry per (thread, stream_id): next
// expected seq, the seq of the final chunk once known, how many chunks
// are currently buffered awaiting gap-fill, and whether reassembly is
// complete) and `stream_chunks` (one entry per buffered-but-not-yet-
// deliverable chunk, deleted the moment it becomes deliverable — this
// bucket only ever holds the §6 "buffered" set, bounded at 65536
// entries per stream, never the full history of a long stream). Full
// permanent history of every chunk envelope already exists independent
// of this file, via RecordThreadEnvelope's unconditional archiving into
// `thread_msgs` — an application that wants the whole reassembled
// stream after the fact can already get it from ThreadMessages, filtered
// by body.stream_id and sorted by body.seq. What this file adds is the
// real-time, gap-free, bounded-memory delivery guarantee §4 requires.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

var (
	bucketStreamMeta   = []byte("stream_meta")
	bucketStreamChunks = []byte("stream_chunks")
)

// MaxBufferedStreamChunks is awp-streaming-v0.1.md §6's fixed bound: "a
// receiver MUST NOT buffer more than 65536 chunks for a single
// stream_id." Not configurable, for the same reason core's own bounds
// aren't (awp-sig's framing: "one fewer knob to misconfigure").
const MaxBufferedStreamChunks = 65536

type streamMetaValue struct {
	NextSeq       int       `json:"next_seq"`
	FinalSeq      int       `json:"final_seq"` // -1 means not yet known
	BufferedCount int       `json:"buffered_count"`
	Complete      bool      `json:"complete"`
	LastSeenTs    time.Time `json:"last_seen_ts"`
}

type streamChunkValue struct {
	Final bool            `json:"final"`
	Data  json.RawMessage `json:"data"`
}

// DeliveredChunk is one chunk that just became safe to deliver to the
// application layer, in order, per awp-streaming-v0.1.md §4.
type DeliveredChunk struct {
	Seq   int
	Final bool
	Data  json.RawMessage
}

// StreamChunkOutcome is IngestStreamChunk's result.
type StreamChunkOutcome struct {
	// Duplicate means seq was already delivered, or is already buffered
	// unchanged — a safe no-op, most commonly caused by a chunk arriving
	// twice under two different envelope ids (the gate's own id-based
	// dedupe, core §2.2 gate 4, only catches the SAME envelope id twice;
	// an application-level resend under a fresh id lands here instead).
	Duplicate bool
	// BoundExceeded means accepting this chunk into the buffer would
	// exceed MaxBufferedStreamChunks — per §6, the ENTIRE reassembly
	// buffer for this stream_id has already been discarded by the time
	// this is returned.
	BoundExceeded bool
	// Deliverable is the newly-contiguous run of chunks this ingestion
	// unlocked, in seq order — empty if this chunk was itself buffered
	// (out-of-order) rather than immediately deliverable, or was a
	// duplicate.
	Deliverable []DeliveredChunk
	// Complete is true once Deliverable's last entry (or an earlier
	// ingestion) included the final chunk with no remaining gap.
	Complete bool
}

func streamKeys(thread, streamID string) (metaKey, chunkPrefix []byte, err error) {
	tKey, err := idKey(thread)
	if err != nil {
		return nil, nil, fmt.Errorf("store: stream thread id: %w", err)
	}
	sKey, err := idKey(streamID)
	if err != nil {
		return nil, nil, fmt.Errorf("store: stream_id: %w", err)
	}
	metaKey = append(append([]byte{}, tKey...), sKey...)
	return metaKey, metaKey, nil
}

func seqKey(prefix []byte, seq int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(seq))
	return append(append([]byte{}, prefix...), buf[:]...)
}

// IngestStreamChunk buffers or delivers one verified stream_chunk body
// (the caller — internal/daemon — has already run it through the
// ordinary core §2.2 gate and independently verified its signature per
// awp-streaming-v0.1.md §3; this function has no signature-checking
// role of its own). seq MUST be >= 0 — the caller validates this from
// the chunk body before calling.
func (s *Store) IngestStreamChunk(thread, streamID string, seq int, final bool, data json.RawMessage, now time.Time) (StreamChunkOutcome, error) {
	return s.ingestStreamChunk(thread, streamID, seq, final, data, now, MaxBufferedStreamChunks)
}

// ingestStreamChunk is IngestStreamChunk's actual implementation, with
// the §6 bound as a parameter — tests exercise the bound-exceeded path
// with a small maxBuffered instead of committing MaxBufferedStreamChunks
// (65536) individual bbolt transactions, which is correct but far too
// slow to run on every test invocation.
func (s *Store) ingestStreamChunk(thread, streamID string, seq int, final bool, data json.RawMessage, now time.Time, maxBuffered int) (StreamChunkOutcome, error) {
	metaKey, chunkPrefix, err := streamKeys(thread, streamID)
	if err != nil {
		return StreamChunkOutcome{}, err
	}

	var outcome StreamChunkOutcome
	err = s.db.Update(func(tx *bbolt.Tx) error {
		metaBucket := tx.Bucket(bucketStreamMeta)
		chunkBucket := tx.Bucket(bucketStreamChunks)

		meta := streamMetaValue{FinalSeq: -1}
		if raw := metaBucket.Get(metaKey); raw != nil {
			if err := json.Unmarshal(raw, &meta); err != nil {
				return fmt.Errorf("store: unmarshal stream_meta: %w", err)
			}
		}

		if meta.Complete {
			outcome = StreamChunkOutcome{Duplicate: true, Complete: true}
			return nil
		}
		if seq < meta.NextSeq {
			outcome = StreamChunkOutcome{Duplicate: true}
			return nil
		}

		ck := seqKey(chunkPrefix, seq)
		if seq > meta.NextSeq {
			// Out of order: buffer it, unless it's a re-arrival of an
			// already-buffered seq (idempotent, no bound impact) or the
			// buffer is already at its §6 bound.
			if chunkBucket.Get(ck) != nil {
				outcome = StreamChunkOutcome{Duplicate: true}
				return nil
			}
			if meta.BufferedCount+1 > maxBuffered {
				if err := discardStreamBuffer(chunkBucket, metaBucket, metaKey, chunkPrefix); err != nil {
					return err
				}
				outcome = StreamChunkOutcome{BoundExceeded: true}
				return nil
			}
			cv := streamChunkValue{Final: final, Data: data}
			buf, err := json.Marshal(cv)
			if err != nil {
				return err
			}
			if err := chunkBucket.Put(ck, buf); err != nil {
				return err
			}
			meta.BufferedCount++
			if final {
				meta.FinalSeq = seq
			}
			meta.LastSeenTs = now
			return putStreamMeta(metaBucket, metaKey, meta)
		}

		// seq == meta.NextSeq: immediately deliverable, possibly
		// cascading into chunks that arrived earlier out of order.
		curSeq, curFinal, curData := seq, final, data
		for {
			outcome.Deliverable = append(outcome.Deliverable, DeliveredChunk{Seq: curSeq, Final: curFinal, Data: curData})
			meta.NextSeq = curSeq + 1
			if curFinal {
				meta.FinalSeq = curSeq
				meta.Complete = true
				break
			}
			nextKey := seqKey(chunkPrefix, curSeq+1)
			bufVal := chunkBucket.Get(nextKey)
			if bufVal == nil {
				break
			}
			var cv streamChunkValue
			if err := json.Unmarshal(bufVal, &cv); err != nil {
				return fmt.Errorf("store: unmarshal buffered stream chunk: %w", err)
			}
			if err := chunkBucket.Delete(nextKey); err != nil {
				return err
			}
			meta.BufferedCount--
			curSeq, curFinal, curData = curSeq+1, cv.Final, cv.Data
		}
		meta.LastSeenTs = now
		outcome.Complete = meta.Complete
		return putStreamMeta(metaBucket, metaKey, meta)
	})
	return outcome, err
}

func putStreamMeta(metaBucket *bbolt.Bucket, key []byte, meta streamMetaValue) error {
	buf, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return metaBucket.Put(key, buf)
}

// discardStreamBuffer implements §6's "the receiver MUST discard its
// reassembly buffer for that stream_id" — every buffered (undelivered)
// chunk between the current delivered watermark and the chunk that
// pushed the stream over the bound, plus the stream's own meta record,
// are removed entirely. A later chunk for the same stream_id starts
// fresh (meta absent), which is the correct outcome for a stream that's
// already been deemed abusive/broken — not "resume where it left off."
func discardStreamBuffer(chunkBucket, metaBucket *bbolt.Bucket, metaKey, chunkPrefix []byte) error {
	c := chunkBucket.Cursor()
	for k, _ := c.Seek(chunkPrefix); k != nil && bytes.HasPrefix(k, chunkPrefix); k, _ = c.Next() {
		if err := chunkBucket.Delete(k); err != nil {
			return err
		}
	}
	return metaBucket.Delete(metaKey)
}

// GCStreamBuffers deletes stream reassembly state for streams that
// haven't seen a new chunk in maxAge and never completed — awp-
// streaming-v0.1.md §5: "A stream that never receives a final:true
// chunk... MUST be treated as failed once every already-received
// chunk's ttl has elapsed with the gap unfilled... detecting an
// incomplete stream is a receiver-local concern." Completed streams'
// meta records are also eventually reclaimed here (their BufferedCount
// is already 0, so there's nothing costly about keeping them — this
// bounds it anyway, exactly as GCDeadLetters bounds dead-letter
// retention). Returns the number of (thread, stream_id) records deleted.
func (s *Store) GCStreamBuffers(now time.Time, maxAge time.Duration) (int, error) {
	var deleted int
	err := s.db.Update(func(tx *bbolt.Tx) error {
		metaBucket := tx.Bucket(bucketStreamMeta)
		chunkBucket := tx.Bucket(bucketStreamChunks)

		var toDelete [][]byte
		if err := metaBucket.ForEach(func(k, v []byte) error {
			var meta streamMetaValue
			if err := json.Unmarshal(v, &meta); err != nil {
				return err
			}
			if now.Sub(meta.LastSeenTs) >= maxAge {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
			return nil
		}); err != nil {
			return err
		}

		for _, metaKey := range toDelete {
			c := chunkBucket.Cursor()
			for k, _ := c.Seek(metaKey); k != nil && bytes.HasPrefix(k, metaKey); k, _ = c.Next() {
				if err := chunkBucket.Delete(k); err != nil {
					return err
				}
			}
			if err := metaBucket.Delete(metaKey); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	return deleted, err
}
