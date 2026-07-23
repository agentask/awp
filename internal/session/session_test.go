package session

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestIssueVerify_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)

	token, err := Issue("01arz3ndektsv4rrffq69g5fav", "caller.example.com", "provider.example.com#tool", expires, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := Verify(token, "caller.example.com", pub, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_TableDriven(t *testing.T) {
	pub, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	validToken, err := Issue("sid1", "caller.example.com", "provider.example.com#tool", now.Add(time.Hour), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	expiredToken, err := Issue("sid2", "caller.example.com", "provider.example.com#tool", now.Add(-time.Hour), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		caller    string
		pub       ed25519.PublicKey
		wantErrIs error
	}{
		{"valid", validToken, "caller.example.com", pub, nil},
		{"expired", expiredToken, "caller.example.com", pub, ErrExpired},
		{"caller mismatch: sessions do not transfer", validToken, "someone-else.example.com", pub, ErrCallerMismatch},
		{"wrong verification key", validToken, "caller.example.com", otherPub, ErrBadSignature},
		{"malformed: no dot separator", "not-a-token", "caller.example.com", pub, ErrMalformed},
		{"malformed: garbage signature segment", validToken[:len(validToken)-5] + "!!!!!", "caller.example.com", pub, nil}, // may be ErrMalformed or ErrBadSignature depending on garbage; checked below
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.token, tt.caller, tt.pub, now)
			if tt.name == "valid" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tt.wantErrIs != nil && err != tt.wantErrIs {
				// ErrMalformed cases are wrapped with fmt.Errorf("%w: ...");
				// use errors.Is semantics via direct wrap check.
				if !isWrapped(err, tt.wantErrIs) {
					t.Fatalf("expected error %v, got %v", tt.wantErrIs, err)
				}
			}
		})
	}
}

func isWrapped(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestVerify_SplicedPayloadRejected swaps in a payload for a different
// caller while keeping the ORIGINAL token's signature attached — a forgery
// attempt distinct from TestVerify_TableDriven's "caller mismatch" case
// (which uses a legitimately-signed token, just checked against the wrong
// expected caller). This must fail signature verification specifically,
// since the attached signature was never computed over the spliced-in
// payload.
func TestVerify_SplicedPayloadRejected(t *testing.T) {
	pub, priv := mustKeypair(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	original, err := Issue("sid1", "caller.example.com", "provider.example.com#tool", now.Add(time.Hour), priv)
	if err != nil {
		t.Fatalf("Issue original: %v", err)
	}
	forged, err := Issue("sid1", "attacker.example.com", "provider.example.com#tool", now.Add(time.Hour), priv)
	if err != nil {
		t.Fatalf("Issue forged: %v", err)
	}

	_, origSig, ok := strings.Cut(original, ".")
	if !ok {
		t.Fatal("original token missing '.' separator")
	}
	forgedPayload, _, ok := strings.Cut(forged, ".")
	if !ok {
		t.Fatal("forged token missing '.' separator")
	}

	spliced := forgedPayload + "." + origSig
	if err := Verify(spliced, "attacker.example.com", pub, now); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature for a spliced payload+foreign signature, got %v", err)
	}
}
