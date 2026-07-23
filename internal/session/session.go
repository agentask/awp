// Package session implements the core §1.3 recommended self-authenticating
// session token: opaque to callers, verifiable by the issuing provider
// without a storage read on the hot path.
package session

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

// payload is the core §1.3 token body: {"sid", "caller", "entity", "expires"}.
type payload struct {
	Sid     string `json:"sid"`
	Caller  string `json:"caller"`
	Entity  string `json:"entity"`
	Expires string `json:"expires"`
}

// Token construction, per core §1.3:
//
//	token = base64url(JCS({"sid","caller","entity","expires"}))
//	        "." base64url(ed25519_sig_by_provider_domain_key)
//
// Spec gap flagged (per CLAUDE.md): the spec doesn't say what bytes the
// signature covers — only that it follows the base64url(JCS(...)) part
// joined by ".". The natural, unambiguous reading (and the one that avoids
// re-deriving JCS bytes from the token string, which would require
// re-encoding rather than just splitting) is JWT-style: the signature
// covers the ASCII bytes of the base64url(JCS(...)) segment itself, not
// the raw JCS bytes underneath it. That's what Issue/Verify implement.

// Issue mints a new session token for (caller, entity), signed by the
// provider's own domain key. The token carries no keyid — core §1.3
// verification resolves "the provider's own current key" out of band, the
// same way any other request-signing key is resolved.
func Issue(sid, caller, entity string, expires time.Time, priv ed25519.PrivateKey) (string, error) {
	p := payload{Sid: sid, Caller: caller, Entity: entity, Expires: expires.UTC().Format(rfc3339Milli)}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("session: marshal payload: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("session: jcs: %w", err)
	}
	payloadB64 := b64Encode(canon)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	return payloadB64 + "." + b64Encode(sig), nil
}

const rfc3339Milli = "2006-01-02T15:04:05.000Z"

var (
	// ErrMalformed means the token isn't of the form payload.signature.
	ErrMalformed = errors.New("session: malformed token")
	// ErrExpired means the token's expires timestamp has passed.
	ErrExpired = errors.New("session: token expired")
	// ErrCallerMismatch means the token's caller doesn't match the
	// request's verified signing principal — core §1.3: "sessions do not
	// transfer."
	ErrCallerMismatch = errors.New("session: caller mismatch")
	// ErrBadSignature means the token's signature doesn't verify.
	ErrBadSignature = errors.New("session: signature verification failed")
)

// Verify decodes and checks a session token: signature (by pub, the
// provider's own current key), expiry (against now), and that caller
// equals the request's verified signing principal. Verification is
// storage-free by design (core §1.3) — callers resolve pub however they
// resolve any other signing key for their own domain.
func Verify(token string, callerPrincipal string, pub ed25519.PublicKey, now time.Time) error {
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok {
		return ErrMalformed
	}
	sig, err := b64Decode(sigB64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !ed25519.Verify(pub, []byte(payloadB64), sig) {
		return ErrBadSignature
	}

	canon, err := b64Decode(payloadB64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var p payload
	if err := json.Unmarshal(canon, &p); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	expires, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil {
		return fmt.Errorf("%w: bad expires: %v", ErrMalformed, err)
	}
	if now.After(expires) {
		return ErrExpired
	}
	if p.Caller != callerPrincipal {
		return ErrCallerMismatch
	}
	return nil
}

func b64Encode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func b64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
