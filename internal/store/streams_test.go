package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func chunkData(t *testing.T, s string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"text": s})
	if err != nil {
		t.Fatalf("marshal chunk data: %v", err)
	}
	return raw
}

// TestIngestStreamChunk_InOrderDelivery covers awp-streaming-v0.1.md §4
// item 3's simplest case: chunks arriving already in order are each
// immediately deliverable, one at a time.
func TestIngestStreamChunk_InOrderDelivery(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	for seq := range 3 {
		final := seq == 2
		out, err := s.IngestStreamChunk(thread, streamID, seq, final, chunkData(t, "x"), now)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if len(out.Deliverable) != 1 || out.Deliverable[0].Seq != seq {
			t.Fatalf("seq %d: expected exactly this seq deliverable immediately, got %+v", seq, out.Deliverable)
		}
		if out.Complete != final {
			t.Fatalf("seq %d: Complete = %v, want %v", seq, out.Complete, final)
		}
	}
}

// TestIngestStreamChunk_OutOfOrderReassembly covers §4 items 1-2:
// out-of-order arrival is buffered, never delivered ahead of a gap, and
// cascades into a single multi-chunk delivery once the gap fills.
func TestIngestStreamChunk_OutOfOrderReassembly(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	// seq 2 arrives first: must NOT be delivered (seq 0,1 missing).
	out, err := s.IngestStreamChunk(thread, streamID, 2, false, chunkData(t, "c"), now)
	if err != nil {
		t.Fatalf("seq 2: %v", err)
	}
	if len(out.Deliverable) != 0 {
		t.Fatalf("seq 2 arrived before 0/1: expected no delivery, got %+v", out.Deliverable)
	}

	// seq 0 arrives: only seq 0 is deliverable (1 is still missing).
	out, err = s.IngestStreamChunk(thread, streamID, 0, false, chunkData(t, "a"), now)
	if err != nil {
		t.Fatalf("seq 0: %v", err)
	}
	if len(out.Deliverable) != 1 || out.Deliverable[0].Seq != 0 {
		t.Fatalf("seq 0: expected exactly seq 0 deliverable, got %+v", out.Deliverable)
	}

	// seq 1 arrives: cascades into delivering 1 AND the already-buffered 2.
	out, err = s.IngestStreamChunk(thread, streamID, 1, false, chunkData(t, "b"), now)
	if err != nil {
		t.Fatalf("seq 1: %v", err)
	}
	if len(out.Deliverable) != 2 || out.Deliverable[0].Seq != 1 || out.Deliverable[1].Seq != 2 {
		t.Fatalf("seq 1: expected cascading delivery of [1,2], got %+v", out.Deliverable)
	}
	if out.Complete {
		t.Fatal("expected Complete=false: no final chunk seen yet")
	}

	// final chunk (seq 3) completes the stream.
	out, err = s.IngestStreamChunk(thread, streamID, 3, true, chunkData(t, "d"), now)
	if err != nil {
		t.Fatalf("seq 3: %v", err)
	}
	if !out.Complete {
		t.Fatal("expected Complete=true after the final chunk")
	}
}

// TestIngestStreamChunk_DuplicateDeliveredSeq covers a chunk resent
// (e.g. under a fresh envelope id) after its seq was already delivered.
func TestIngestStreamChunk_DuplicateDeliveredSeq(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	if _, err := s.IngestStreamChunk(thread, streamID, 0, false, chunkData(t, "a"), now); err != nil {
		t.Fatalf("seq 0: %v", err)
	}
	out, err := s.IngestStreamChunk(thread, streamID, 0, false, chunkData(t, "a"), now)
	if err != nil {
		t.Fatalf("seq 0 resend: %v", err)
	}
	if !out.Duplicate || len(out.Deliverable) != 0 {
		t.Fatalf("expected Duplicate=true, no re-delivery, got %+v", out)
	}
}

// TestIngestStreamChunk_DuplicateBufferedSeq covers an out-of-order
// chunk resent while still buffered (not yet deliverable).
func TestIngestStreamChunk_DuplicateBufferedSeq(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	if _, err := s.IngestStreamChunk(thread, streamID, 5, false, chunkData(t, "x"), now); err != nil {
		t.Fatalf("seq 5: %v", err)
	}
	out, err := s.IngestStreamChunk(thread, streamID, 5, false, chunkData(t, "x"), now)
	if err != nil {
		t.Fatalf("seq 5 resend: %v", err)
	}
	if !out.Duplicate {
		t.Fatalf("expected Duplicate=true for a resent buffered seq, got %+v", out)
	}
}

// TestIngestStreamChunk_CompleteStreamIgnoresFurtherChunks covers a
// chunk arriving after the stream already reassembled completely.
func TestIngestStreamChunk_CompleteStreamIgnoresFurtherChunks(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	if _, err := s.IngestStreamChunk(thread, streamID, 0, true, chunkData(t, "only"), now); err != nil {
		t.Fatalf("seq 0 (final): %v", err)
	}
	out, err := s.IngestStreamChunk(thread, streamID, 1, false, chunkData(t, "late"), now)
	if err != nil {
		t.Fatalf("seq 1 after completion: %v", err)
	}
	if !out.Duplicate || !out.Complete || len(out.Deliverable) != 0 {
		t.Fatalf("expected a no-op on a completed stream, got %+v", out)
	}
}

// TestIngestStreamChunk_BoundExceededDiscardsBuffer covers awp-
// streaming-v0.1.md §6: exceeding the buffered (undelivered) chunk bound
// discards the ENTIRE buffer, and a fresh chunk for the same stream_id
// afterward starts over rather than resuming. Uses ingestStreamChunk's
// unexported maxBuffered parameter with a small bound — exercising the
// exact same code path MaxBufferedStreamChunks (65536) would, without
// committing tens of thousands of individual bbolt transactions on every
// test run.
func TestIngestStreamChunk_BoundExceededDiscardsBuffer(t *testing.T) {
	s, _ := openTestStore(t)
	thread, streamID := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	const smallBound = 5

	// Never send seq 0, so every subsequent seq stays buffered
	// (undelivered) rather than cascading through.
	for seq := 1; seq <= smallBound; seq++ {
		out, err := s.ingestStreamChunk(thread, streamID, seq, false, chunkData(t, "x"), now, smallBound)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if out.BoundExceeded {
			t.Fatalf("bound tripped early at seq %d (buffered so far: %d, want up to %d)", seq, seq, smallBound)
		}
	}

	out, err := s.ingestStreamChunk(thread, streamID, smallBound+1, false, chunkData(t, "x"), now, smallBound)
	if err != nil {
		t.Fatalf("overflow chunk: %v", err)
	}
	if !out.BoundExceeded {
		t.Fatal("expected BoundExceeded=true once the buffer would exceed the bound")
	}

	// A fresh chunk for the same stream_id after discard starts over:
	// seq 0 is immediately deliverable (as if this were a brand new
	// stream), not "resuming" the discarded buffer.
	out, err = s.ingestStreamChunk(thread, streamID, 0, false, chunkData(t, "restart"), now, smallBound)
	if err != nil {
		t.Fatalf("post-discard seq 0: %v", err)
	}
	if len(out.Deliverable) != 1 || out.Deliverable[0].Seq != 0 {
		t.Fatalf("expected the stream to restart cleanly at seq 0, got %+v", out)
	}
}

// TestIngestStreamChunk_DefaultBoundIsSpecMandated confirms the public
// IngestStreamChunk entry point actually uses MaxBufferedStreamChunks
// (65536), not some other default — a fast, single-call check that the
// wiring in IngestStreamChunk itself (as opposed to the bound-exceeded
// LOGIC, covered above with a small bound) didn't drift from the spec
// constant.
func TestIngestStreamChunk_DefaultBoundIsSpecMandated(t *testing.T) {
	if MaxBufferedStreamChunks != 65536 {
		t.Fatalf("MaxBufferedStreamChunks = %d, want 65536 (awp-streaming-v0.1.md §6)", MaxBufferedStreamChunks)
	}
}

// TestIngestStreamChunk_DistinctStreamsIndependent confirms two
// different (thread, stream_id) pairs never interfere with each other's
// reassembly state, including two different streams on the SAME thread.
func TestIngestStreamChunk_DistinctStreamsIndependent(t *testing.T) {
	s, _ := openTestStore(t)
	thread := envelope.NewID()
	streamA, streamB := envelope.NewID(), envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	if _, err := s.IngestStreamChunk(thread, streamA, 0, false, chunkData(t, "a0"), now); err != nil {
		t.Fatalf("stream A seq 0: %v", err)
	}
	// Stream B's seq 0 must be independently deliverable even though
	// stream A is mid-flight on the same thread.
	out, err := s.IngestStreamChunk(thread, streamB, 0, false, chunkData(t, "b0"), now)
	if err != nil {
		t.Fatalf("stream B seq 0: %v", err)
	}
	if len(out.Deliverable) != 1 {
		t.Fatalf("expected stream B's seq 0 delivered independently of stream A, got %+v", out)
	}
}

// TestGCStreamBuffers_DeletesOnlyStaleIncompleteStreams covers §5:
// abandoned (no final chunk, no recent activity) streams are reclaimed;
// recently-active or completed streams are left alone.
func TestGCStreamBuffers_DeletesOnlyStaleIncompleteStreams(t *testing.T) {
	s, _ := openTestStore(t)
	thread := envelope.NewID()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	staleStream := envelope.NewID()
	if _, err := s.IngestStreamChunk(thread, staleStream, 5, false, chunkData(t, "x"), now.Add(-25*time.Hour)); err != nil {
		t.Fatalf("stale stream ingest: %v", err)
	}
	freshStream := envelope.NewID()
	if _, err := s.IngestStreamChunk(thread, freshStream, 5, false, chunkData(t, "x"), now.Add(-time.Hour)); err != nil {
		t.Fatalf("fresh stream ingest: %v", err)
	}

	deleted, err := s.GCStreamBuffers(now, 24*time.Hour)
	if err != nil {
		t.Fatalf("GCStreamBuffers: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly 1 stream reclaimed, got %d", deleted)
	}

	// The stale stream's buffered chunk is gone: seq 0 through 5 arriving
	// now must be treated as fresh, not cascade into an old buffered 5.
	out, err := s.IngestStreamChunk(thread, staleStream, 0, false, chunkData(t, "restart"), now)
	if err != nil {
		t.Fatalf("post-GC seq 0: %v", err)
	}
	if len(out.Deliverable) != 1 || out.Deliverable[0].Seq != 0 {
		t.Fatalf("expected only seq 0 deliverable (old buffered seq 5 must be gone), got %+v", out)
	}

	// The fresh stream's buffered seq 5 must still be there.
	out, err = s.IngestStreamChunk(thread, freshStream, 0, false, chunkData(t, "0"), now)
	if err != nil {
		t.Fatalf("fresh stream seq 0: %v", err)
	}
	seqs := make([]int, len(out.Deliverable))
	for i, c := range out.Deliverable {
		seqs[i] = c.Seq
	}
	if len(seqs) != 1 || seqs[0] != 0 {
		t.Fatalf("expected only seq 0 delivered (seq 1-4 still missing, 5 still buffered), got %+v", seqs)
	}
}
