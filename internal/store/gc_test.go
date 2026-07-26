package store

import (
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func TestGCSeen_DeletesOnlyExpiredEntries(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	expiredID := envelope.NewID()
	if _, err := s.AcceptInbound(expiredID, now.Add(-time.Hour), []byte("{}")); err != nil {
		t.Fatalf("AcceptInbound expired: %v", err)
	}
	liveID := envelope.NewID()
	if _, err := s.AcceptInbound(liveID, now.Add(time.Hour), []byte("{}")); err != nil {
		t.Fatalf("AcceptInbound live: %v", err)
	}

	deleted, err := s.GCSeen(now)
	if err != nil {
		t.Fatalf("GCSeen: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}

	seenExpired, err := s.HasSeen(expiredID)
	if err != nil {
		t.Fatalf("HasSeen expired: %v", err)
	}
	if seenExpired {
		t.Fatal("expected the expired seen-id to be gone")
	}
	seenLive, err := s.HasSeen(liveID)
	if err != nil {
		t.Fatalf("HasSeen live: %v", err)
	}
	if !seenLive {
		t.Fatal("expected the still-live seen-id to be retained (never delete before expiry)")
	}
}

func TestGCSeen_NoOpWhenNothingExpired(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := envelope.NewID()
	if _, err := s.AcceptInbound(id, now.Add(time.Hour), []byte("{}")); err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}
	deleted, err := s.GCSeen(now)
	if err != nil {
		t.Fatalf("GCSeen: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted, got %d", deleted)
	}
}

func TestGCDeadLetters_DeletesOnlyPastRetention(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	retention := 720 * time.Hour

	oldDead := envelope.NewID()
	if err := s.EnqueueOutbound(oldDead, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDead(oldDead, "expired", "ttl", now.Add(-retention).Add(-time.Hour)); err != nil {
		t.Fatalf("MarkDead old: %v", err)
	}

	recentDead := envelope.NewID()
	if err := s.EnqueueOutbound(recentDead, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDead(recentDead, "rejected", "403", now.Add(-time.Hour)); err != nil {
		t.Fatalf("MarkDead recent: %v", err)
	}

	stillQueued := envelope.NewID()
	if err := s.EnqueueOutbound(stillQueued, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	deleted, err := s.GCDeadLetters(now, retention)
	if err != nil {
		t.Fatalf("GCDeadLetters: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}

	if _, found, _ := s.GetOutbox(oldDead); found {
		t.Fatal("expected the past-retention dead letter to be gone")
	}
	if _, found, _ := s.GetOutbox(recentDead); !found {
		t.Fatal("expected the within-retention dead letter to remain")
	}
	if _, found, _ := s.GetOutbox(stillQueued); !found {
		t.Fatal("GC must never touch a non-dead (queued) record")
	}
}
