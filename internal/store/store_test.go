package store

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"go.etcd.io/bbolt"

	"github.com/agentask/awp/internal/envelope"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "awpd.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestOpen_CreatesBucketsAndSchema(t *testing.T) {
	s, path := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Reopen: should succeed and preserve schema version.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
}

func TestOpen_RejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awpd.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Manually bump the schema version past what this binary supports.
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatalf("reopen raw: %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, schemaVersion+1)
		return tx.Bucket(bucketMeta).Put(metaSchemaKey, buf)
	})
	if err != nil {
		t.Fatalf("bump schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("expected Open to reject a newer schema version")
	}
}

func TestAcceptInbound_WritesBothSeenAndInq(t *testing.T) {
	s, _ := openTestStore(t)
	id := envelope.NewID()
	expiry := time.Now().Add(time.Hour)
	raw := []byte(`{"id":"` + id + `"}`)

	alreadySeen, err := s.AcceptInbound(id, expiry, raw)
	if err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}
	if alreadySeen {
		t.Fatal("expected alreadySeen=false on first accept")
	}

	seen, err := s.HasSeen(id)
	if err != nil || !seen {
		t.Fatalf("HasSeen: %v, %v", seen, err)
	}
	queued, err := s.HasQueued(id)
	if err != nil || !queued {
		t.Fatalf("HasQueued: %v, %v", queued, err)
	}
}

func TestAcceptInbound_DedupesSecondArrival(t *testing.T) {
	s, _ := openTestStore(t)
	id := envelope.NewID()
	expiry := time.Now().Add(time.Hour)
	original := []byte(`{"id":"` + id + `","v":1}`)

	if _, err := s.AcceptInbound(id, expiry, original); err != nil {
		t.Fatalf("first accept: %v", err)
	}

	// Same id arrives again with different bytes (shouldn't happen per
	// spec — envelopes are immutable after signing — but the dedupe check
	// must still short-circuit rather than overwrite).
	duplicate := []byte(`{"id":"` + id + `","v":2}`)
	alreadySeen, err := s.AcceptInbound(id, expiry, duplicate)
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if !alreadySeen {
		t.Fatal("expected alreadySeen=true on duplicate id")
	}

	// The originally stored bytes must be untouched.
	var stored []byte
	key, _ := idKey(id)
	err = s.db.View(func(tx *bbolt.Tx) error {
		stored = append([]byte{}, tx.Bucket(bucketInq).Get(key)...)
		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if string(stored) != string(original) {
		t.Fatalf("inq entry was overwritten: got %s, want %s", stored, original)
	}
}

func TestIdKey_RejectsNonULID(t *testing.T) {
	if _, err := idKey("not-a-ulid"); err == nil {
		t.Fatal("expected error for malformed id")
	}
}

func TestIdKey_RoundTripsCanonicalBytes(t *testing.T) {
	id := envelope.NewID()
	k1, err := idKey(id)
	if err != nil {
		t.Fatalf("idKey: %v", err)
	}
	// Re-derive from the parsed ULID directly to confirm idKey's bytes
	// match the canonical ULID byte form (used for lexical/arrival order).
	parsed, err := ulid.ParseStrict(ulidUpper(id))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	k2 := parsed.Bytes()
	if string(k1) != string(k2) {
		t.Fatalf("idKey bytes don't match canonical ULID bytes")
	}
}

func ulidUpper(id string) string {
	b := []byte(id)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
