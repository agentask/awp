// Package envelope implements the AWP core §2.1 envelope: types, JCS
// canon, sign/verify, and ULID id generation.
package envelope

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/identity"
)

// MaxSize is the core §2.1 serialized-envelope cap.
const MaxSize = 256 * 1024

// MinTTL and MaxTTL are the core §2.1 ttl bounds, in seconds.
const (
	MinTTL = 60
	MaxTTL = 604800
)

// Envelope is the unit of async communication (core §2.1).
type Envelope struct {
	Awp        string            `json:"awp"`
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	Thread     string            `json:"thread"`
	InReplyTo  *string           `json:"in_reply_to"`
	Ts         string            `json:"ts"`
	TTL        int               `json:"ttl"`
	Session    *string           `json:"session"`
	Delegation []delegation.Link `json:"delegation"`
	Body       json.RawMessage   `json:"body"`
	Sig        *identity.Sig     `json:"sig,omitempty"`
}

// NewID generates a sender-side envelope id: a lowercase Crockford base32
// ULID (core §0: "All ordering-sensitive IDs are ULIDs, lowercase Crockford
// base32").
func NewID() string {
	return strings.ToLower(ulid.Make().String())
}

// Sign attaches env.Sig per core §0.1, signed by domainOf(env.From)'s key.
func (e *Envelope) Sign(priv ed25519.PrivateKey, kid string) error {
	sig, err := identity.Sign(e, priv, kid)
	if err != nil {
		return err
	}
	e.Sig = sig
	return nil
}

// Verify checks e.Sig against pub. Callers resolve pub via
// (identity.DomainOf(e.From), e.Sig.Kid) against the sender's domain index.
func (e *Envelope) Verify(pub ed25519.PublicKey) error {
	if e.Sig == nil {
		return fmt.Errorf("envelope: %q has no sig", e.ID)
	}
	return identity.VerifySig(e, e.Sig, pub)
}

// ErrTooLarge is returned by ValidateSize when the serialized envelope
// exceeds MaxSize.
var ErrTooLarge = errors.New("envelope: exceeds 256 KiB size limit")

// ErrTTLOutOfBounds is returned by ValidateTTL when ttl falls outside
// [MinTTL, MaxTTL].
var ErrTTLOutOfBounds = errors.New("envelope: ttl out of bounds [60, 604800]")

// ValidateTTL enforces the core §2.1 ttl bounds.
func (e *Envelope) ValidateTTL() error {
	if e.TTL < MinTTL || e.TTL > MaxTTL {
		return ErrTTLOutOfBounds
	}
	return nil
}

// ValidateSize enforces the core §2.1 256 KiB serialized-size cap.
func (e *Envelope) ValidateSize() error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("envelope: marshal for size check: %w", err)
	}
	if len(raw) > MaxSize {
		return ErrTooLarge
	}
	return nil
}
