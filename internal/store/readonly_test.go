package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOpenReadOnly_ReadsExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awpd.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := "01arz3ndektsv4rrffq69g5fav"
	if err := s.EnqueueOutbound(id, []byte("{}"), now); err != nil {
		t.Fatalf("EnqueueOutbound: %v", err)
	}
	if err := s.MarkDead(id, "expired", "ttl exceeded"); err != nil {
		t.Fatalf("MarkDead: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer ro.Close()

	dead, err := ro.ListDead()
	if err != nil {
		t.Fatalf("ListDead: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != id {
		t.Fatalf("expected 1 dead record with id %s, got %+v", id, dead)
	}
}

func TestOpenReadOnly_RejectsWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awpd.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer ro.Close()

	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if err := ro.EnqueueOutbound("01arz3ndektsv4rrffq69g5fbv", []byte("{}"), now); err == nil {
		t.Fatal("expected a write to a read-only store to fail")
	}
}

func TestOpenReadOnly_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.db")
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("expected an error opening a nonexistent file read-only")
	}
}
