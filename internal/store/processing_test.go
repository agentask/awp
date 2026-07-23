package store

import (
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func TestClaimAndCompleteInbound(t *testing.T) {
	s, _ := openTestStore(t)
	id := envelope.NewID()
	raw := []byte(`{"id":"` + id + `"}`)
	if _, err := s.AcceptInbound(id, time.Now().Add(time.Hour), raw); err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}

	claimed, err := s.ClaimInbound(10)
	if err != nil {
		t.Fatalf("ClaimInbound: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("expected 1 claimed record with id %s, got %+v", id, claimed)
	}
	if string(claimed[0].Envelope) != string(raw) {
		t.Fatalf("claimed envelope bytes mismatch")
	}

	// Claimed items must not be reclaimed.
	claimedAgain, err := s.ClaimInbound(10)
	if err != nil {
		t.Fatalf("ClaimInbound (again): %v", err)
	}
	if len(claimedAgain) != 0 {
		t.Fatalf("expected 0 records on second claim, got %+v", claimedAgain)
	}

	if err := s.CompleteInbound(id); err != nil {
		t.Fatalf("CompleteInbound: %v", err)
	}

	recovered, err := s.InboundBootRecovery()
	if err != nil {
		t.Fatalf("InboundBootRecovery: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("expected 0 recovered after completion, got %d", recovered)
	}
}

func TestInboundBootRecovery_RestoresUncompletedClaims(t *testing.T) {
	s, _ := openTestStore(t)
	id := envelope.NewID()
	if _, err := s.AcceptInbound(id, time.Now().Add(time.Hour), []byte("{}")); err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}
	if _, err := s.ClaimInbound(10); err != nil {
		t.Fatalf("ClaimInbound: %v", err)
	}
	// Simulate a crash: never call CompleteInbound.

	recovered, err := s.InboundBootRecovery()
	if err != nil {
		t.Fatalf("InboundBootRecovery: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("expected 1 record recovered, got %d", recovered)
	}

	queued, err := s.HasQueued(id)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if !queued {
		t.Fatal("expected the record back in inq after boot recovery")
	}

	// Now claimable again.
	claimed, err := s.ClaimInbound(10)
	if err != nil {
		t.Fatalf("ClaimInbound: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("expected the recovered record to be claimable, got %+v", claimed)
	}
}

func TestClaimInbound_RespectsLimit(t *testing.T) {
	s, _ := openTestStore(t)
	for range 5 {
		id := envelope.NewID()
		if _, err := s.AcceptInbound(id, time.Now().Add(time.Hour), []byte("{}")); err != nil {
			t.Fatalf("AcceptInbound: %v", err)
		}
	}
	claimed, err := s.ClaimInbound(3)
	if err != nil {
		t.Fatalf("ClaimInbound: %v", err)
	}
	if len(claimed) != 3 {
		t.Fatalf("expected 3 claimed (limit), got %d", len(claimed))
	}
	rest, err := s.ClaimInbound(10)
	if err != nil {
		t.Fatalf("ClaimInbound (rest): %v", err)
	}
	if len(rest) != 2 {
		t.Fatalf("expected 2 remaining claimed, got %d", len(rest))
	}
}
