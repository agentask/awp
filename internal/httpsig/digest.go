// Package httpsig implements the awp-sig-v0.1.md sync signing profile: a
// minimal, hand-rolled RFC 9421 subset. Per CLAUDE.md: "This subset IS the
// spec: anything outside it MUST be rejected" — no negotiation, no
// algorithm agility, so this package is deliberately narrow rather than a
// general-purpose HTTP-message-signatures library.
package httpsig

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrDigestMismatch means a recomputed Content-Digest doesn't match the
// header value.
var ErrDigestMismatch = errors.New("httpsig: content-digest mismatch")

// ComputeContentDigest returns the RFC 9530 sha-256 Content-Digest header
// value for body: "sha-256=:<standard-base64 digest>:".
func ComputeContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// VerifyContentDigest checks header against body, sha-256 only (awp-sig
// §1.3: "RFC 9530, sha-256 only").
func VerifyContentDigest(header string, body []byte) error {
	want := ComputeContentDigest(body)
	if header != want {
		return fmt.Errorf("%w: got %q, want %q", ErrDigestMismatch, header, want)
	}
	return nil
}
