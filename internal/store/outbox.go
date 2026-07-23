package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"go.etcd.io/bbolt"
)

// OutboxState is one of the awpd-outbox-v0.1.md §1 state machine states.
type OutboxState string

const (
	StateQueued       OutboxState = "queued"
	StateDelivering   OutboxState = "delivering"
	StateDelivered    OutboxState = "delivered"
	StateDeadExpired  OutboxState = "dead_expired"
	StateDeadRejected OutboxState = "dead_rejected"
)

// OutboxRecord is one delivery record, as read back from the `outbox`
// bucket (awpd-store §2 `outbox`).
type OutboxRecord struct {
	ID         string
	Envelope   []byte
	State      OutboxState
	Attempts   int
	NextAt     time.Time
	LastErr    string
	DeadReason string
}

// outboxValue is OutboxRecord's on-disk JSON shape (ID is the bucket key,
// not stored redundantly in the value).
type outboxValue struct {
	Envelope   []byte      `json:"envelope"`
	State      OutboxState `json:"state"`
	Attempts   int         `json:"attempts"`
	NextAt     time.Time   `json:"next_at"`
	LastErr    string      `json:"last_err"`
	DeadReason string      `json:"dead_reason,omitempty"`
}

func ulidString(idBytes []byte) string {
	var u ulid.ULID
	copy(u[:], idBytes)
	return strings.ToLower(u.String())
}

// schedKey is `next_at (8B big-endian ms) ++ ULID`, per awpd-store §2
// `outbox_sched` — sorts by delivery due-time first, so the delivery loop
// can read the bucket head instead of scanning `outbox`.
func schedKey(nextAt time.Time, id []byte) []byte {
	buf := make([]byte, 8+len(id))
	binary.BigEndian.PutUint64(buf[:8], uint64(nextAt.UnixMilli()))
	copy(buf[8:], id)
	return buf
}

func toRecord(id string, v outboxValue) OutboxRecord {
	return OutboxRecord{
		ID:         id,
		Envelope:   v.Envelope,
		State:      v.State,
		Attempts:   v.Attempts,
		NextAt:     v.NextAt,
		LastErr:    v.LastErr,
		DeadReason: v.DeadReason,
	}
}

// EnqueueOutbound writes a new outbox record and its schedule entry in one
// transaction (awpd-store §3 "Outbound enqueue").
func (s *Store) EnqueueOutbound(id string, envelope []byte, nextAt time.Time) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	val := outboxValue{Envelope: envelope, State: StateQueued, NextAt: nextAt}
	buf, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("store: marshal outbox value: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket(bucketOutbox).Put(key, buf); err != nil {
			return fmt.Errorf("store: put outbox: %w", err)
		}
		return tx.Bucket(bucketOutboxSched).Put(schedKey(nextAt, key), []byte{})
	})
}

// MarkDelivering claims a queued record (awpd-outbox §1: queued ->
// delivering) and removes its schedule entry — while delivering, it must
// not be re-selected by DueForDelivery.
func (s *Store) MarkDelivering(id string) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		ob := tx.Bucket(bucketOutbox)
		raw := ob.Get(key)
		if raw == nil {
			return fmt.Errorf("store: outbox record %q not found", id)
		}
		var v outboxValue
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		oldSched := schedKey(v.NextAt, key)
		v.State = StateDelivering
		buf, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if err := ob.Put(key, buf); err != nil {
			return err
		}
		return tx.Bucket(bucketOutboxSched).Delete(oldSched)
	})
}

// MarkDelivered removes a successfully delivered record — terminal, no
// retention requirement (unlike dead letters, awpd-outbox §2 rule 7).
func (s *Store) MarkDelivered(id string) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketOutbox).Delete(key)
	})
}

// MarkRetry returns a record to `queued` with an incremented attempt count
// and a new schedule entry (awpd-store §3 "Retry reschedule").
func (s *Store) MarkRetry(id string, nextAt time.Time, lastErr string) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		ob := tx.Bucket(bucketOutbox)
		raw := ob.Get(key)
		if raw == nil {
			return fmt.Errorf("store: outbox record %q not found", id)
		}
		var v outboxValue
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		v.State = StateQueued
		v.Attempts++
		v.NextAt = nextAt
		v.LastErr = lastErr
		buf, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if err := ob.Put(key, buf); err != nil {
			return err
		}
		return tx.Bucket(bucketOutboxSched).Put(schedKey(nextAt, key), []byte{})
	})
}

// MarkDead moves a record to a terminal dead state (awpd-outbox §2 rule 7:
// dead letters are kept, not deleted, until explicit GC). reason must be
// "expired" or "rejected"; any other value is treated as "rejected".
func (s *Store) MarkDead(id string, reason string, lastErr string) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		ob := tx.Bucket(bucketOutbox)
		raw := ob.Get(key)
		if raw == nil {
			return fmt.Errorf("store: outbox record %q not found", id)
		}
		var v outboxValue
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if v.State == StateQueued {
			// Pre-attempt expiry: the record was never claimed, so its
			// schedule entry is still live and must be removed.
			if err := tx.Bucket(bucketOutboxSched).Delete(schedKey(v.NextAt, key)); err != nil {
				return err
			}
		}
		if reason == "expired" {
			v.State = StateDeadExpired
		} else {
			v.State = StateDeadRejected
		}
		v.DeadReason = lastErr
		v.LastErr = lastErr
		buf, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return ob.Put(key, buf)
	})
}

// DueForDelivery returns up to limit queued records whose schedule time has
// arrived, in due-time order. It reads only `outbox_sched` (awpd-store §2:
// "the delivery loop reads the head of this bucket — never scans outbox").
func (s *Store) DueForDelivery(now time.Time, limit int) ([]OutboxRecord, error) {
	var out []OutboxRecord
	nowMillis := uint64(now.UnixMilli())
	err := s.db.View(func(tx *bbolt.Tx) error {
		sched := tx.Bucket(bucketOutboxSched)
		ob := tx.Bucket(bucketOutbox)
		c := sched.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(out) >= limit {
				break
			}
			if len(k) < 8 {
				continue
			}
			if binary.BigEndian.Uint64(k[:8]) > nowMillis {
				break // keys are sorted by next_at; nothing further is due
			}
			idBytes := k[8:]
			raw := ob.Get(idBytes)
			if raw == nil {
				continue
			}
			var v outboxValue
			if err := json.Unmarshal(raw, &v); err != nil {
				continue
			}
			out = append(out, toRecord(ulidString(idBytes), v))
		}
		return nil
	})
	return out, err
}

// GetOutbox returns the current outbox record for id, if any.
func (s *Store) GetOutbox(id string) (OutboxRecord, bool, error) {
	key, err := idKey(id)
	if err != nil {
		return OutboxRecord{}, false, err
	}
	var rec OutboxRecord
	var found bool
	err = s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bucketOutbox).Get(key)
		if raw == nil {
			return nil
		}
		found = true
		var v outboxValue
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		rec = toRecord(id, v)
		return nil
	})
	return rec, found, err
}

// ListDead returns every record in a terminal dead state (the store-level
// primitive behind `awp outbox ls --dead`).
func (s *Store) ListDead() ([]OutboxRecord, error) {
	var out []OutboxRecord
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketOutbox).ForEach(func(k, v []byte) error {
			var val outboxValue
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			if val.State == StateDeadExpired || val.State == StateDeadRejected {
				out = append(out, toRecord(ulidString(k), val))
			}
			return nil
		})
	})
	return out, err
}

// BootRecovery moves every `delivering` record back to `queued` with
// next_at=now, re-adding its schedule entry, in one transaction
// (awpd-outbox §2 rule 6 / awpd-store §3 "Boot recovery": "a crash mid-
// request is indistinguishable from a network failure"). Returns the
// number of records recovered.
func (s *Store) BootRecovery(now time.Time) (int, error) {
	var recovered int
	err := s.db.Update(func(tx *bbolt.Tx) error {
		ob := tx.Bucket(bucketOutbox)
		sched := tx.Bucket(bucketOutboxSched)

		type pending struct {
			key []byte
			val outboxValue
		}
		var toUpdate []pending
		if err := ob.ForEach(func(k, v []byte) error {
			var val outboxValue
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			if val.State == StateDelivering {
				toUpdate = append(toUpdate, pending{key: append([]byte{}, k...), val: val})
			}
			return nil
		}); err != nil {
			return err
		}

		for _, p := range toUpdate {
			p.val.State = StateQueued
			p.val.NextAt = now
			buf, err := json.Marshal(p.val)
			if err != nil {
				return err
			}
			if err := ob.Put(p.key, buf); err != nil {
				return err
			}
			if err := sched.Put(schedKey(now, p.key), []byte{}); err != nil {
				return err
			}
			recovered++
		}
		return nil
	})
	return recovered, err
}
