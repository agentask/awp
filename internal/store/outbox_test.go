package store

import (
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func TestEnqueueOutbound_DueForDelivery(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := envelope.NewID()
	raw := []byte(`{"id":"` + id + `"}`)

	if err := s.EnqueueOutbound(id, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	due, err := s.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 1 || due[0].ID != id {
		t.Fatalf("expected 1 due record with id %s, got %+v", id, due)
	}
	if due[0].State != StateQueued {
		t.Fatalf("expected state queued, got %s", due[0].State)
	}

	// Not yet due.
	notYet, err := s.DueForDelivery(now.Add(-time.Second), 10)
	if err != nil {
		t.Fatalf("DueForDelivery early: %v", err)
	}
	if len(notYet) != 0 {
		t.Fatalf("expected no due records before next_at, got %d", len(notYet))
	}
}

func TestMarkDelivering_RemovesFromSchedule(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := envelope.NewID()
	if err := s.EnqueueOutbound(id, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDelivering(id); err != nil {
		t.Fatalf("MarkDelivering: %v", err)
	}

	due, err := s.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("delivering record must not be re-selected, got %+v", due)
	}

	rec, found, err := s.GetOutbox(id)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v, found=%v", err, found)
	}
	if rec.State != StateDelivering {
		t.Fatalf("expected state delivering, got %s", rec.State)
	}
}

func TestMarkDelivered_RemovesRecord(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := envelope.NewID()
	if err := s.EnqueueOutbound(id, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDelivering(id); err != nil {
		t.Fatalf("MarkDelivering: %v", err)
	}
	if err := s.MarkDelivered(id); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	_, found, err := s.GetOutbox(id)
	if err != nil {
		t.Fatalf("GetOutbox: %v", err)
	}
	if found {
		t.Fatal("expected delivered record to be removed")
	}
}

func TestMarkRetry_ReschedulesAndIncrementsAttempts(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	id := envelope.NewID()
	if err := s.EnqueueOutbound(id, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDelivering(id); err != nil {
		t.Fatalf("MarkDelivering: %v", err)
	}
	retryAt := now.Add(5 * time.Second)
	if err := s.MarkRetry(id, retryAt, "connection refused"); err != nil {
		t.Fatalf("MarkRetry: %v", err)
	}

	rec, found, err := s.GetOutbox(id)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v, found=%v", err, found)
	}
	if rec.State != StateQueued || rec.Attempts != 1 || !rec.NextAt.Equal(retryAt) {
		t.Fatalf("unexpected record after retry: %+v", rec)
	}

	due, err := s.DueForDelivery(retryAt, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 1 || due[0].ID != id {
		t.Fatalf("expected the retried record to be due again, got %+v", due)
	}
}

func TestMarkDead_TableDriven(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		claimFirst bool // MarkDelivering before MarkDead, simulating dead-after-attempt
		wantState  OutboxState
	}{
		{"dead from queued (pre-attempt expiry)", false, StateDeadExpired},
		{"dead from delivering (post-attempt rejection)", true, StateDeadRejected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := openTestStore(t)
			id := envelope.NewID()
			if err := s.EnqueueOutbound(id, []byte("{}"), now); err != nil {
				t.Fatalf("enqueue: %v", err)
			}
			if tt.claimFirst {
				if err := s.MarkDelivering(id); err != nil {
					t.Fatalf("MarkDelivering: %v", err)
				}
			}
			reason := "rejected"
			if !tt.claimFirst {
				reason = "expired"
			}
			if err := s.MarkDead(id, reason, "detail", now); err != nil {
				t.Fatalf("MarkDead: %v", err)
			}

			rec, found, err := s.GetOutbox(id)
			if err != nil || !found {
				t.Fatalf("GetOutbox: %v, found=%v", err, found)
			}
			if rec.State != tt.wantState {
				t.Fatalf("expected state %s, got %s", tt.wantState, rec.State)
			}

			// A dead record must never be re-selected for delivery.
			due, err := s.DueForDelivery(now.Add(24*time.Hour), 10)
			if err != nil {
				t.Fatalf("DueForDelivery: %v", err)
			}
			if len(due) != 0 {
				t.Fatalf("dead record must not be due, got %+v", due)
			}

			dead, err := s.ListDead()
			if err != nil {
				t.Fatalf("ListDead: %v", err)
			}
			if len(dead) != 1 || dead[0].ID != id {
				t.Fatalf("expected dead record %s in ListDead, got %+v", id, dead)
			}
		})
	}
}

// EARS gate: WHEN the daemon restarts mid-delivery, in-flight records SHALL
// return to queued with next_at=now.
func TestBootRecovery_DeliveringReturnsToQueuedWithNextAtNow(t *testing.T) {
	s, _ := openTestStore(t)
	enqueuedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	restartAt := enqueuedAt.Add(90 * time.Second) // simulates time passing during the crash

	id := envelope.NewID()
	if err := s.EnqueueOutbound(id, []byte("{}"), enqueuedAt); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if err := s.MarkDelivering(id); err != nil {
		t.Fatalf("MarkDelivering: %v", err)
	}

	// Simulate the crash: nothing more happens to this record until boot.
	recovered, err := s.BootRecovery(restartAt)
	if err != nil {
		t.Fatalf("BootRecovery: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("expected 1 record recovered, got %d", recovered)
	}

	rec, found, err := s.GetOutbox(id)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v, found=%v", err, found)
	}
	if rec.State != StateQueued {
		t.Fatalf("expected state queued after boot recovery, got %s", rec.State)
	}
	if !rec.NextAt.Equal(restartAt) {
		t.Fatalf("expected next_at=%v (restart time), got %v", restartAt, rec.NextAt)
	}

	due, err := s.DueForDelivery(restartAt, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 1 || due[0].ID != id {
		t.Fatalf("expected recovered record to be immediately due, got %+v", due)
	}
}

func TestBootRecovery_LeavesQueuedAndDeadUntouched(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	queuedID := envelope.NewID()
	if err := s.EnqueueOutbound(queuedID, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue queued: %v", err)
	}
	deadID := envelope.NewID()
	if err := s.EnqueueOutbound(deadID, []byte("{}"), now); err != nil {
		t.Fatalf("enqueue dead: %v", err)
	}
	if err := s.MarkDead(deadID, "expired", "ttl", now); err != nil {
		t.Fatalf("MarkDead: %v", err)
	}

	recovered, err := s.BootRecovery(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("BootRecovery: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("expected 0 records recovered (nothing was delivering), got %d", recovered)
	}

	queuedRec, _, _ := s.GetOutbox(queuedID)
	if !queuedRec.NextAt.Equal(now) {
		t.Fatalf("boot recovery must not touch already-queued records' next_at, got %v", queuedRec.NextAt)
	}
	deadRec, _, _ := s.GetOutbox(deadID)
	if deadRec.State != StateDeadExpired {
		t.Fatalf("boot recovery must not touch dead records, got state %s", deadRec.State)
	}
}
