package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// Thread is a thread's current state, as read back from `threads`.
type Thread struct {
	ID       string
	Peer     string
	OpenedTs time.Time
	Closed   bool
	ClosedBy string
	LastTs   time.Time
	LastID   string
}

type threadValue struct {
	Peer     string    `json:"peer"`
	OpenedTs time.Time `json:"opened_ts"`
	Closed   bool      `json:"closed"`
	ClosedBy string    `json:"closed_by,omitempty"`
	LastTs   time.Time `json:"last_ts"`
	LastID   string    `json:"last_id"`
}

// ErrThreadPeerMismatch is returned when an envelope's (from, to) pair
// doesn't match a thread's already-established peer — the awpd-store §2
// two-party invariant: "an envelope whose (from,to) don't match peer is a
// protocol error (error(refused)), not a silent merge."
var ErrThreadPeerMismatch = errors.New("store: envelope peer does not match thread's established peer")

// RecordThreadEnvelope opens threadID if this is its first envelope (peer
// becomes the other party), or enforces the two-party invariant if it
// already exists, then archives envRaw into `thread_msgs` and updates
// last_ts/last_id — all in one transaction. If isClose, the thread is
// marked closed by closedBy.
//
// Spec note (flagged per CLAUDE.md: spec wins, gaps get flagged not
// silently resolved): awpd-store-v0.1.md §2 describes `thread_msgs`'s value
// as "envelope ULID (ref into the archived envelope)", implying envelopes
// live on permanently in some other bucket a thread can point into. No such
// bucket is defined anywhere in that spec — `inq`/`inq_active` are deleted
// on completion and `outbox` is deleted on delivery, so nothing durable
// survives processing to be "referenced into". This implementation stores
// the full raw envelope bytes directly as `thread_msgs`'s value instead of
// an ID reference, which is the only reading that makes "archived" true
// rather than aspirational. The key still carries the envelope ULID
// (thread ULID ++ envelope ULID), so ID-only lookups remain possible
// without decoding the value.
func (s *Store) RecordThreadEnvelope(threadID, peer, envID string, envRaw []byte, ts time.Time, isClose bool, closedBy string) error {
	tKey, err := idKey(threadID)
	if err != nil {
		return fmt.Errorf("store: thread id: %w", err)
	}
	eKey, err := idKey(envID)
	if err != nil {
		return fmt.Errorf("store: envelope id: %w", err)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		threads := tx.Bucket(bucketThreads)
		raw := threads.Get(tKey)

		var tv threadValue
		if raw == nil {
			tv = threadValue{Peer: peer, OpenedTs: ts}
		} else {
			if err := json.Unmarshal(raw, &tv); err != nil {
				return err
			}
			if tv.Peer != peer {
				return ErrThreadPeerMismatch
			}
		}
		tv.LastTs = ts
		tv.LastID = envID
		if isClose {
			tv.Closed = true
			tv.ClosedBy = closedBy
		}

		buf, err := json.Marshal(tv)
		if err != nil {
			return err
		}
		if err := threads.Put(tKey, buf); err != nil {
			return err
		}

		msgKey := append(append([]byte{}, tKey...), eKey...)
		return tx.Bucket(bucketThreadMsgs).Put(msgKey, envRaw)
	})
}

// GetThread returns a thread's current state.
func (s *Store) GetThread(threadID string) (Thread, bool, error) {
	key, err := idKey(threadID)
	if err != nil {
		return Thread{}, false, err
	}
	var th Thread
	var found bool
	err = s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bucketThreads).Get(key)
		if raw == nil {
			return nil
		}
		found = true
		var tv threadValue
		if err := json.Unmarshal(raw, &tv); err != nil {
			return err
		}
		th = Thread{
			ID: threadID, Peer: tv.Peer, OpenedTs: tv.OpenedTs,
			Closed: tv.Closed, ClosedBy: tv.ClosedBy,
			LastTs: tv.LastTs, LastID: tv.LastID,
		}
		return nil
	})
	return th, found, err
}

// ThreadMessage is one archived envelope within a thread.
type ThreadMessage struct {
	ID       string
	Envelope []byte
}

// ThreadMessages returns the envelopes archived under threadID, in arrival
// order (awpd-store §2: "Prefix range scan returns the conversation in
// (ts,id) order because ULIDs sort lexically by time"). The id comes from
// the key suffix, not the value — see RecordThreadEnvelope's doc comment
// for why the value is the raw envelope, not an id reference.
func (s *Store) ThreadMessages(threadID string) ([]ThreadMessage, error) {
	prefix, err := idKey(threadID)
	if err != nil {
		return nil, err
	}
	var msgs []ThreadMessage
	err = s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketThreadMsgs).Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			id := ulidString(k[len(prefix):])
			msgs = append(msgs, ThreadMessage{ID: id, Envelope: append([]byte{}, v...)})
		}
		return nil
	})
	return msgs, err
}
