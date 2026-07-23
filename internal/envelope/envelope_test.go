package envelope

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"

	"github.com/agentask/awp/internal/identity"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func testEnvelope() *Envelope {
	return &Envelope{
		Awp:        "0.1",
		ID:         NewID(),
		Kind:       "message",
		From:       "assistant.acme.com#scheduler",
		To:         "example.com#generate-invoice",
		Thread:     NewID(),
		InReplyTo:  nil,
		Ts:         "2026-07-21T09:14:03.512Z",
		TTL:        3600,
		Session:    nil,
		Delegation: nil,
		Body:       json.RawMessage(`{"type":"text","text":"hello"}`),
	}
}

// EARS gate 1: round-trip sign->verify byte-identical JCS canon and
// verifies.
func TestEnvelopeSignVerify_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	e := testEnvelope()

	canonBefore, err := identity.CanonicalBytes(e)
	if err != nil {
		t.Fatalf("canon before sign: %v", err)
	}

	if err := e.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}

	canonAfter, err := identity.CanonicalBytes(e)
	if err != nil {
		t.Fatalf("canon after sign: %v", err)
	}
	if string(canonBefore) != string(canonAfter) {
		t.Fatalf("canon changed after signing:\nbefore: %s\nafter:  %s", canonBefore, canonAfter)
	}

	if err := e.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Round-trip through JSON (simulating wire transmission) preserves
	// byte-identical canon and a verifying signature.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var e2 Envelope
	if err := json.Unmarshal(raw, &e2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	canon2, err := identity.CanonicalBytes(&e2)
	if err != nil {
		t.Fatalf("canon e2: %v", err)
	}
	if string(canonAfter) != string(canon2) {
		t.Fatalf("canon not byte-identical after wire round-trip")
	}
	if err := e2.Verify(pub); err != nil {
		t.Fatalf("verify e2: %v", err)
	}
}

func TestEnvelopeVerify_RejectsTamperedContent(t *testing.T) {
	pub, priv := mustKeypair(t)
	e := testEnvelope()
	if err := e.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	e.Body = json.RawMessage(`{"type":"text","text":"tampered"}`)
	if err := e.Verify(pub); err == nil {
		t.Fatal("expected verification failure on tampered body")
	}
}

func TestNewID_IsLowercaseCrockfordULID(t *testing.T) {
	id := NewID()
	if id != strings.ToLower(id) {
		t.Fatalf("id %q is not lowercase", id)
	}
	if len(id) != ulid.EncodedSize {
		t.Fatalf("id %q has length %d, want %d", id, len(id), ulid.EncodedSize)
	}
	if _, err := ulid.ParseStrict(strings.ToUpper(id)); err != nil {
		t.Fatalf("id %q is not a valid ULID: %v", id, err)
	}
}

func TestNewID_Unique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestValidateTTL_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		ttl     int
		wantErr bool
	}{
		{"minimum valid", MinTTL, false},
		{"maximum valid", MaxTTL, false},
		{"mid-range valid", 3600, false},
		{"below minimum", MinTTL - 1, true},
		{"above maximum", MaxTTL + 1, true},
		{"zero", 0, true},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := testEnvelope()
			e.TTL = tt.ttl
			err := e.ValidateTTL()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for ttl=%d", tt.ttl)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for ttl=%d: %v", tt.ttl, err)
			}
		})
	}
}

func TestValidateSize_TableDriven(t *testing.T) {
	small := testEnvelope()

	oversized := testEnvelope()
	oversized.Body = json.RawMessage(`"` + strings.Repeat("x", MaxSize) + `"`)

	tests := []struct {
		name    string
		env     *Envelope
		wantErr bool
	}{
		{"small envelope", small, false},
		{"oversized body", oversized, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.env.ValidateSize()
			if tt.wantErr && err == nil {
				t.Fatal("expected size error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
