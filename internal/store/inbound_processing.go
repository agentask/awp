package store

import (
	"fmt"

	"go.etcd.io/bbolt"
)

// InboundRecord is one claimed inbound envelope, as read back from
// `inq`/`inq_active`.
type InboundRecord struct {
	ID       string
	Envelope []byte
}

// ClaimInbound moves up to limit envelopes from `inq` to `inq_active`
// (awpd-store §2 "Claim: move key inq -> inq_active in one tx") and returns
// them for processing, in arrival order (ULID keys sort by time).
func (s *Store) ClaimInbound(limit int) ([]InboundRecord, error) {
	var out []InboundRecord
	err := s.db.Update(func(tx *bbolt.Tx) error {
		inq := tx.Bucket(bucketInq)
		active := tx.Bucket(bucketInqActive)

		var keys, vals [][]byte
		c := inq.Cursor()
		for k, v := c.First(); k != nil && len(keys) < limit; k, v = c.Next() {
			keys = append(keys, append([]byte{}, k...))
			vals = append(vals, append([]byte{}, v...))
		}
		for i, k := range keys {
			if err := active.Put(k, vals[i]); err != nil {
				return fmt.Errorf("store: put inq_active: %w", err)
			}
			if err := inq.Delete(k); err != nil {
				return fmt.Errorf("store: delete inq: %w", err)
			}
			out = append(out, InboundRecord{ID: ulidString(k), Envelope: vals[i]})
		}
		return nil
	})
	return out, err
}

// CompleteInbound removes a claimed envelope from `inq_active`
// (awpd-store §2 "Complete: delete from inq_active + write thread updates,
// same tx" — callers pair this with RecordThreadEnvelope in the same
// processing step at the application layer; both are individually atomic
// bbolt txs here rather than one combined tx, since thread state can
// legitimately be recorded even if the caller later fails before calling
// CompleteInbound — at-least-once processing, per awpd-store §2 "Semantics
// are at-least-once; processing MUST be idempotent per envelope id").
func (s *Store) CompleteInbound(id string) error {
	key, err := idKey(id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketInqActive).Delete(key)
	})
}

// InboundBootRecovery moves everything still in `inq_active` back to `inq`
// (awpd-store §2: "Boot recovery: everything in inq_active moves back to
// inq"). Returns the number of records recovered.
func (s *Store) InboundBootRecovery() (int, error) {
	var recovered int
	err := s.db.Update(func(tx *bbolt.Tx) error {
		active := tx.Bucket(bucketInqActive)
		inq := tx.Bucket(bucketInq)

		var keys, vals [][]byte
		if err := active.ForEach(func(k, v []byte) error {
			keys = append(keys, append([]byte{}, k...))
			vals = append(vals, append([]byte{}, v...))
			return nil
		}); err != nil {
			return err
		}
		for i, k := range keys {
			if err := inq.Put(k, vals[i]); err != nil {
				return err
			}
			if err := active.Delete(k); err != nil {
				return err
			}
			recovered++
		}
		return nil
	})
	return recovered, err
}
