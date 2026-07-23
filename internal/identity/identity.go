// Package identity implements the AWP core §0.1 signing primitive, the
// domain index / key types of §1.1, and rotation/revocation/expiry
// verification.
package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gowebpki/jcs"
)

// Sig is the {kid, value} signature envelope used by every signed object
// (index, manifest, envelope, delegation link) per core §0.1.
type Sig struct {
	Kid   string `json:"kid"`
	Value string `json:"value"`
}

// DomainOf strips the "#entity" fragment from a principal name, per core §0.
func DomainOf(principal string) string {
	domain, _, _ := strings.Cut(principal, "#")
	return domain
}

// CanonicalBytes marshals v to JSON, removes any top-level "sig" member, and
// applies JCS (RFC 8785) to produce the exact bytes that are signed/verified
// per core §0.1.
func CanonicalBytes(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("identity: unmarshal for sig strip: %w", err)
	}
	delete(m, "sig")
	stripped, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("identity: remarshal: %w", err)
	}
	canon, err := jcs.Transform(stripped)
	if err != nil {
		return nil, fmt.Errorf("identity: jcs: %w", err)
	}
	return canon, nil
}

// Sign produces the Sig for v under priv, keyed by kid. v's own "sig" field
// (if present) is ignored/stripped before signing.
func Sign(v any, priv ed25519.PrivateKey, kid string) (*Sig, error) {
	canon, err := CanonicalBytes(v)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &Sig{Kid: kid, Value: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

// ErrBadSignature is returned when a signature fails Ed25519 verification.
var ErrBadSignature = errors.New("identity: signature verification failed")

// VerifySig recomputes v's canonical bytes (with "sig" stripped, regardless
// of what v currently carries) and checks sig against pub.
func VerifySig(v any, sig *Sig, pub ed25519.PublicKey) error {
	if sig == nil {
		return errors.New("identity: nil signature")
	}
	canon, err := CanonicalBytes(v)
	if err != nil {
		return err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("identity: decode sig value: %w", err)
	}
	if !ed25519.Verify(pub, canon, sigBytes) {
		return ErrBadSignature
	}
	return nil
}
