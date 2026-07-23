package store

import (
	"encoding/json"
	"time"

	"go.etcd.io/bbolt"
)

type keysCacheValue struct {
	IndexJSON []byte    `json:"index_json"`
	FetchedAt time.Time `json:"fetched_at"`
	ETag      string    `json:"etag,omitempty"`
}

// GetKeysCache returns a domain's cached signed index document (raw JSON
// bytes, as fetched), if present.
func (s *Store) GetKeysCache(domain string) ([]byte, bool, error) {
	var raw []byte
	var found bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketKeysCache).Get([]byte(domain))
		if v == nil {
			return nil
		}
		found = true
		var cv keysCacheValue
		if err := json.Unmarshal(v, &cv); err != nil {
			return err
		}
		raw = cv.IndexJSON
		return nil
	})
	return raw, found, err
}

// PutKeysCache caches domain's fetched index document.
func (s *Store) PutKeysCache(domain string, indexJSON []byte, fetchedAt time.Time, etag string) error {
	cv := keysCacheValue{IndexJSON: indexJSON, FetchedAt: fetchedAt, ETag: etag}
	buf, err := json.Marshal(cv)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketKeysCache).Put([]byte(domain), buf)
	})
}

// DeleteKeysCache evicts domain's cache entry — the core §0.1 rotation-race
// "Refresh(domain)" primitive (awpd-store §2: "deletes then re-fetches").
func (s *Store) DeleteKeysCache(domain string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketKeysCache).Delete([]byte(domain))
	})
}
