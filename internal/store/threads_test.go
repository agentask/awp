package store

import (
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func TestRecordThreadEnvelope_OpensAndAppends(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	thread := envelope.NewID()
	msg1 := envelope.NewID()
	msg2 := envelope.NewID()

	if err := s.RecordThreadEnvelope(thread, "peer.example.com", msg1, []byte("env1"), now, false, ""); err != nil {
		t.Fatalf("record msg1: %v", err)
	}
	if err := s.RecordThreadEnvelope(thread, "peer.example.com", msg2, []byte("env2"), now.Add(time.Second), false, ""); err != nil {
		t.Fatalf("record msg2: %v", err)
	}

	th, found, err := s.GetThread(thread)
	if err != nil || !found {
		t.Fatalf("GetThread: %v, found=%v", err, found)
	}
	if th.Peer != "peer.example.com" || th.Closed || th.LastID != msg2 {
		t.Fatalf("unexpected thread state: %+v", th)
	}
	if !th.OpenedTs.Equal(now) {
		t.Fatalf("expected opened_ts=%v, got %v", now, th.OpenedTs)
	}

	msgs, err := s.ThreadMessages(thread)
	if err != nil {
		t.Fatalf("ThreadMessages: %v", err)
	}
	if len(msgs) != 2 || msgs[0].ID != msg1 || msgs[1].ID != msg2 {
		t.Fatalf("expected [%s, %s] in order, got %+v", msg1, msg2, msgs)
	}
	if string(msgs[0].Envelope) != "env1" || string(msgs[1].Envelope) != "env2" {
		t.Fatalf("archived envelope bytes don't match what was recorded: %+v", msgs)
	}
}

func TestRecordThreadEnvelope_ClosesThread(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	thread := envelope.NewID()
	msg1 := envelope.NewID()
	closeID := envelope.NewID()

	if err := s.RecordThreadEnvelope(thread, "peer.example.com", msg1, []byte("m"), now, false, ""); err != nil {
		t.Fatalf("record msg1: %v", err)
	}
	if err := s.RecordThreadEnvelope(thread, "peer.example.com", closeID, []byte("c"), now.Add(time.Minute), true, "peer.example.com"); err != nil {
		t.Fatalf("record close: %v", err)
	}

	th, found, err := s.GetThread(thread)
	if err != nil || !found {
		t.Fatalf("GetThread: %v, found=%v", err, found)
	}
	if !th.Closed || th.ClosedBy != "peer.example.com" {
		t.Fatalf("expected thread closed by peer.example.com, got %+v", th)
	}
}

// awpd-store §2 two-party invariant: an envelope whose peer doesn't match
// an already-established thread is a protocol error, not a silent merge.
func TestRecordThreadEnvelope_RejectsPeerMismatch(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	thread := envelope.NewID()
	msg1 := envelope.NewID()
	msg2 := envelope.NewID()

	if err := s.RecordThreadEnvelope(thread, "a.example.com", msg1, []byte("m1"), now, false, ""); err != nil {
		t.Fatalf("record msg1: %v", err)
	}
	err := s.RecordThreadEnvelope(thread, "b.example.com", msg2, []byte("m2"), now.Add(time.Second), false, "")
	if err != ErrThreadPeerMismatch {
		t.Fatalf("expected ErrThreadPeerMismatch, got %v", err)
	}

	// The mismatched envelope must not have been recorded.
	msgs, err := s.ThreadMessages(thread)
	if err != nil {
		t.Fatalf("ThreadMessages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].ID != msg1 {
		t.Fatalf("expected only msg1 recorded, got %+v", msgs)
	}
}

func TestThreadMessages_SeparatesDifferentThreads(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	threadA := envelope.NewID()
	threadB := envelope.NewID()
	msgA := envelope.NewID()
	msgB := envelope.NewID()

	if err := s.RecordThreadEnvelope(threadA, "peer.example.com", msgA, []byte("a"), now, false, ""); err != nil {
		t.Fatalf("record A: %v", err)
	}
	if err := s.RecordThreadEnvelope(threadB, "peer.example.com", msgB, []byte("b"), now, false, ""); err != nil {
		t.Fatalf("record B: %v", err)
	}

	msgsA, err := s.ThreadMessages(threadA)
	if err != nil {
		t.Fatalf("ThreadMessages A: %v", err)
	}
	if len(msgsA) != 1 || msgsA[0].ID != msgA {
		t.Fatalf("thread A leaked cross-thread messages: %+v", msgsA)
	}
}
