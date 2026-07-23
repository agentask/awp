package store

import (
	"testing"
	"time"
)

func TestKeysCache_RoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	_, found, err := s.GetKeysCache("example.com")
	if err != nil {
		t.Fatalf("GetKeysCache (miss): %v", err)
	}
	if found {
		t.Fatal("expected cache miss before any Put")
	}

	indexJSON := []byte(`{"awp":"0.1","domain":"example.com"}`)
	if err := s.PutKeysCache("example.com", indexJSON, now, "etag-1"); err != nil {
		t.Fatalf("PutKeysCache: %v", err)
	}

	got, found, err := s.GetKeysCache("example.com")
	if err != nil || !found {
		t.Fatalf("GetKeysCache: %v, found=%v", err, found)
	}
	if string(got) != string(indexJSON) {
		t.Fatalf("cached index mismatch: got %s, want %s", got, indexJSON)
	}
}

func TestKeysCache_DeleteEvicts(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if err := s.PutKeysCache("example.com", []byte(`{}`), now, ""); err != nil {
		t.Fatalf("PutKeysCache: %v", err)
	}
	if err := s.DeleteKeysCache("example.com"); err != nil {
		t.Fatalf("DeleteKeysCache: %v", err)
	}
	_, found, err := s.GetKeysCache("example.com")
	if err != nil {
		t.Fatalf("GetKeysCache: %v", err)
	}
	if found {
		t.Fatal("expected cache miss after delete")
	}
}
