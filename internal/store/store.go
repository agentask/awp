// Package store implements the awpd bbolt persistence layout of
// awpd-store-v0.1.md. Implemented: `meta`, `seen`, `inq`, `inq_active`
// (Phase 2/4), `outbox`/`outbox_sched` (Phase 3), and `threads`,
// `thread_msgs`, `keys_cache` (Phase 4). `sessions` remains deferred — it
// backs `state: provider` apps, which no phase through the v0.1.0-m1
// milestone exercises.
package store

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"go.etcd.io/bbolt"
)

// schemaVersion is written to the meta bucket on first open. Opening a DB
// with a newer schema than this binary supports MUST fail (awpd-store §2
// meta).
const schemaVersion = 1

var (
	bucketMeta        = []byte("meta")
	bucketSeen        = []byte("seen")
	bucketInq         = []byte("inq")
	bucketInqActive   = []byte("inq_active")
	bucketOutbox      = []byte("outbox")
	bucketOutboxSched = []byte("outbox_sched")
	bucketThreads     = []byte("threads")
	bucketThreadMsgs  = []byte("thread_msgs")
	bucketKeysCache   = []byte("keys_cache")
)

// bucketStreamMeta and bucketStreamChunks (awp-streaming-v0.1.md §4/§6)
// are declared in streams.go, alongside the logic that uses them.

var metaSchemaKey = []byte("schema")

// Store wraps a single bbolt database file (awpd-store §1: one DB file,
// single writer).
type Store struct {
	db *bbolt.DB
}

// Open opens (creating if absent) the bbolt store at path and ensures its
// bucket layout and schema version.
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing store file without acquiring bbolt's
// write lock, so a CLI (e.g. `awp outbox ls --dead`) can inspect a live
// awpd's data file without contending with the daemon's own writer. It
// does not create the file or its buckets — the daemon must have already
// initialized them.
func OpenReadOnly(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) init() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{
			bucketMeta, bucketSeen, bucketInq, bucketInqActive,
			bucketOutbox, bucketOutboxSched,
			bucketThreads, bucketThreadMsgs, bucketKeysCache,
			bucketStreamMeta, bucketStreamChunks,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("store: create bucket %s: %w", b, err)
			}
		}
		meta := tx.Bucket(bucketMeta)
		existing := meta.Get(metaSchemaKey)
		if existing == nil {
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, schemaVersion)
			return meta.Put(metaSchemaKey, buf)
		}
		version := binary.BigEndian.Uint64(existing)
		if version > schemaVersion {
			return fmt.Errorf("store: schema version %d is newer than this binary supports (%d)", version, schemaVersion)
		}
		return nil
	})
}

// Close closes the underlying bbolt database.
func (s *Store) Close() error {
	return s.db.Close()
}

// idKey decodes an envelope ULID string into its canonical 16-byte form,
// used as the key in `seen` and `inq` (awpd-store §2: "ULID ⇒ arrival-
// ordered iteration for free").
func idKey(id string) ([]byte, error) {
	parsed, err := ulid.ParseStrict(strings.ToUpper(id))
	if err != nil {
		return nil, fmt.Errorf("store: id %q is not a valid ULID: %w", id, err)
	}
	return parsed.Bytes(), nil
}

// AcceptInbound performs core §2.2 gate 4 (dedupe on id) and gate 5
// (durable enqueue) as a single bbolt transaction, per awpd-store §2/§3:
// "gate 4 and gate 5 ... are atomic; a crash between them cannot produce an
// acked-but-lost or processed-twice envelope." If id is already present in
// `seen`, alreadySeen is true and nothing is written (dedupe hit). Otherwise
// both `seen` (keyed by id, valued by its expiry) and `inq` (keyed by id,
// valued by the raw envelope bytes) are written before the transaction
// commits; a crash before commit leaves neither.
func (s *Store) AcceptInbound(id string, expiry time.Time, raw []byte) (alreadySeen bool, err error) {
	key, err := idKey(id)
	if err != nil {
		return false, err
	}
	expBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(expBuf, uint64(expiry.Unix()))

	err = s.db.Update(func(tx *bbolt.Tx) error {
		seen := tx.Bucket(bucketSeen)
		if seen.Get(key) != nil {
			alreadySeen = true
			return nil
		}
		if err := seen.Put(key, expBuf); err != nil {
			return fmt.Errorf("store: put seen: %w", err)
		}
		if err := tx.Bucket(bucketInq).Put(key, raw); err != nil {
			return fmt.Errorf("store: put inq: %w", err)
		}
		return nil
	})
	return alreadySeen, err
}

// HasSeen reports whether id is present in the dedupe bucket.
func (s *Store) HasSeen(id string) (bool, error) {
	key, err := idKey(id)
	if err != nil {
		return false, err
	}
	var found bool
	err = s.db.View(func(tx *bbolt.Tx) error {
		found = tx.Bucket(bucketSeen).Get(key) != nil
		return nil
	})
	return found, err
}

// HasQueued reports whether id is present in the inbound processing queue.
func (s *Store) HasQueued(id string) (bool, error) {
	key, err := idKey(id)
	if err != nil {
		return false, err
	}
	var found bool
	err = s.db.View(func(tx *bbolt.Tx) error {
		found = tx.Bucket(bucketInq).Get(key) != nil
		return nil
	})
	return found, err
}

// GCSeen deletes `seen` entries whose expiry has passed (awpd-store §2:
// "GC: hourly cursor scan deleting expired keys"). Retention itself is
// enforced simply by never calling this before an id's own expiry —
// AcceptInbound's expiry value already IS the retention horizon, so there
// is no separate "retention window" to configure beyond it. Returns the
// number of entries deleted.
func (s *Store) GCSeen(now time.Time) (int, error) {
	nowUnix := uint64(now.Unix())
	var deleted int
	err := s.db.Update(func(tx *bbolt.Tx) error {
		seen := tx.Bucket(bucketSeen)
		var toDelete [][]byte
		c := seen.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) < 8 {
				continue
			}
			expiry := binary.BigEndian.Uint64(v)
			if expiry < nowUnix {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
		}
		for _, k := range toDelete {
			if err := seen.Delete(k); err != nil {
				return err
			}
			deleted++
		}
		return nil
	})
	return deleted, err
}
