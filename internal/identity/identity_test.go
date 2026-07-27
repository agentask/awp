package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

func encodePub(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// --- EARS gate 1: round-trip sign->verify produces byte-identical JCS canon
// and verifies. ---

type dummyObj struct {
	Awp   string `json:"awp"`
	Name  string `json:"name"`
	Value int    `json:"value"`
	Sig   *Sig   `json:"sig,omitempty"`
}

func TestRoundTripSignVerify_ByteIdenticalCanon(t *testing.T) {
	pub, priv := mustKeypair(t)

	obj := &dummyObj{Awp: "0.1", Name: "example.com#tool", Value: 42}

	canonBefore, err := CanonicalBytes(obj)
	if err != nil {
		t.Fatalf("canon before sign: %v", err)
	}

	sig, err := Sign(obj, priv, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	obj.Sig = sig

	canonAfter, err := CanonicalBytes(obj)
	if err != nil {
		t.Fatalf("canon after sign: %v", err)
	}

	if string(canonBefore) != string(canonAfter) {
		t.Fatalf("canon bytes changed after attaching sig:\nbefore: %s\nafter:  %s", canonBefore, canonAfter)
	}

	if err := VerifySig(obj, obj.Sig, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Re-sign independently and confirm byte-identical canon + signature
	// verifies against a freshly rebuilt object (simulates a different
	// process reconstructing the same document).
	obj2 := &dummyObj{Awp: "0.1", Name: "example.com#tool", Value: 42, Sig: sig}
	canon2, err := CanonicalBytes(obj2)
	if err != nil {
		t.Fatalf("canon obj2: %v", err)
	}
	if string(canonAfter) != string(canon2) {
		t.Fatalf("canon not byte-identical across independent reconstructions")
	}
	if err := VerifySig(obj2, obj2.Sig, pub); err != nil {
		t.Fatalf("verify obj2: %v", err)
	}
}

func TestVerifySig_RejectsTamperedContent(t *testing.T) {
	pub, priv := mustKeypair(t)
	obj := &dummyObj{Awp: "0.1", Name: "example.com#tool", Value: 42}
	sig, err := Sign(obj, priv, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	obj.Value = 43 // tamper after signing
	if err := VerifySig(obj, sig, pub); err == nil {
		t.Fatal("expected verification failure on tampered content")
	}
}

func TestVerifySig_RejectsWrongKey(t *testing.T) {
	_, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t)
	obj := &dummyObj{Awp: "0.1", Name: "example.com#tool", Value: 42}
	sig, err := Sign(obj, priv, "k1")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifySig(obj, sig, otherPub); err == nil {
		t.Fatal("expected verification failure against wrong key")
	}
}

func TestIndexSelfSignVerify_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	idx := &Index{
		Awp:     "0.1",
		Domain:  "example.com",
		Updated: "2026-07-21T09:00:00.000Z",
		Keys: []Key{
			{Kid: "2026-07-01", Alg: "ed25519", Pub: encodePub(pub), Created: "2026-07-01T00:00:00.000Z"},
		},
		Inbox: "https://example.com/awp/inbox",
	}
	if err := idx.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign index: %v", err)
	}
	if err := idx.VerifySelfSig(); err != nil {
		t.Fatalf("verify index: %v", err)
	}
}

// TestIndexCapabilities_SignedAndVerified confirms the awp-capabilities-v0.1
// Index.Capabilities field round-trips through sign/verify like any other
// index field — it's inside the signed document, not an exception.
func TestIndexCapabilities_SignedAndVerified(t *testing.T) {
	pub, priv := mustKeypair(t)
	idx := &Index{
		Awp:     "0.1",
		Domain:  "example.com",
		Updated: "2026-07-21T09:00:00.000Z",
		Keys: []Key{
			{Kid: "2026-07-01", Alg: "ed25519", Pub: encodePub(pub), Created: "2026-07-01T00:00:00.000Z"},
		},
		Inbox:        "https://example.com/awp/inbox",
		Capabilities: []string{"awp-streaming-v0.1", "awp-kinds-v0.1/status"},
	}
	if err := idx.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign index: %v", err)
	}
	if err := idx.VerifySelfSig(); err != nil {
		t.Fatalf("verify index: %v", err)
	}

	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTripped Index
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := roundTripped.VerifySelfSig(); err != nil {
		t.Fatalf("verify round-tripped index: %v", err)
	}

	// Tampering with capabilities after signing must invalidate the sig —
	// this field is inside the signed document, not bolted on beside it.
	roundTripped.Capabilities = []string{"forged-capability"}
	if err := roundTripped.VerifySelfSig(); err == nil {
		t.Fatal("expected tampered capabilities to invalidate the signature")
	}
}

// --- EARS gate 2: a rotation chain with one broken link rejects. ---

func TestVerifyRotationChain_TableDriven(t *testing.T) {
	rootPub, rootPriv := mustKeypair(t)
	k1Pub, k1Priv := mustKeypair(t)
	k2Pub, _ := mustKeypair(t)
	wrongPub, wrongPriv := mustKeypair(t)

	rootKey := Key{Kid: "root", Alg: "ed25519", Pub: encodePub(rootPub)}

	validK1PrevSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPriv, k1Pub))
	validK1 := Key{Kid: "k1", Alg: "ed25519", Pub: encodePub(k1Pub), PrevSig: &validK1PrevSig}

	validK2PrevSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k1Priv, k2Pub))
	validK2 := Key{Kid: "k2", Alg: "ed25519", Pub: encodePub(k2Pub), PrevSig: &validK2PrevSig}

	// signed by the wrong key entirely
	badSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(wrongPriv, k1Pub))
	brokenK1 := Key{Kid: "k1", Alg: "ed25519", Pub: encodePub(k1Pub), PrevSig: &badSig}

	// prev_sig present but signs different bytes (tampered pub claim)
	tamperedSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPriv, wrongPub))
	tamperedK1 := Key{Kid: "k1", Alg: "ed25519", Pub: encodePub(k1Pub), PrevSig: &tamperedSig}

	noPrevSigK1 := Key{Kid: "k1", Alg: "ed25519", Pub: encodePub(k1Pub)}

	badB64 := "not-valid-base64!!"
	malformedK1 := Key{Kid: "k1", Alg: "ed25519", Pub: encodePub(k1Pub), PrevSig: &badB64}

	tests := []struct {
		name    string
		chain   []Key
		wantErr bool
	}{
		{"valid single-link chain", []Key{rootKey, validK1}, false},
		{"valid two-link chain", []Key{rootKey, validK1, validK2}, false},
		{"root only, no rotation, valid", []Key{rootKey}, false},
		{"broken link: wrong signer", []Key{rootKey, brokenK1}, true},
		{"broken link: tampered pub claim", []Key{rootKey, tamperedK1}, true},
		{"broken link: missing prev_sig", []Key{rootKey, noPrevSigK1}, true},
		{"broken link: malformed prev_sig", []Key{rootKey, malformedK1}, true},
		{"broken link: valid first hop, broken second", []Key{rootKey, validK1, brokenK1}, true},
		{"empty chain", []Key{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyRotationChain(tt.chain)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyRotationChain_IdentifiesBrokenIndex(t *testing.T) {
	rootPub, rootPriv := mustKeypair(t)
	k1Pub, k1Priv := mustKeypair(t)
	k2Pub, _ := mustKeypair(t)
	wrongPub, _ := mustKeypair(t)

	rootKey := Key{Kid: "root", Alg: "ed25519", Pub: encodePub(rootPub)}
	validK1PrevSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPriv, k1Pub))
	validK1 := Key{Kid: "k1", Pub: encodePub(k1Pub), PrevSig: &validK1PrevSig}

	// link 2 is broken: prev_sig doesn't match k1's key over k2's pub
	badSig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(k1Priv, wrongPub))
	brokenK2 := Key{Kid: "k2", Pub: encodePub(k2Pub), PrevSig: &badSig}

	err := VerifyRotationChain([]Key{rootKey, validK1, brokenK2})
	if err == nil {
		t.Fatal("expected error")
	}
	rot, ok := err.(*ErrBrokenRotation)
	if !ok {
		t.Fatalf("expected *ErrBrokenRotation, got %T: %v", err, err)
	}
	if rot.Index != 2 {
		t.Fatalf("expected broken link identified at index 2, got %d", rot.Index)
	}
}

// --- core §1.1 rule 3: revocation / expiry postdates/predates. ---

func TestKeyValid_RevocationAndExpiry(t *testing.T) {
	t0 := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	before := t0.Add(-time.Hour)
	after := t0.Add(time.Hour)
	expiresStr := t0.Format(time.RFC3339)

	tests := []struct {
		name      string
		key       Key
		revokedAt *time.Time
		objTs     time.Time
		wantErr   bool
	}{
		{"not revoked, no expiry", Key{}, nil, t0, false},
		{"revoked, objTs predates revocation: accepted", Key{Revoked: true}, &t0, before, false},
		{"revoked, objTs postdates revocation: rejected", Key{Revoked: true}, &t0, after, true},
		{"revoked, objTs equals revocation instant: accepted (not after)", Key{Revoked: true}, &t0, t0, false},
		{"revoked, unknown revocation instant: fail closed", Key{Revoked: true}, nil, before, true},
		{"expires, objTs predates expiry: accepted", Key{Expires: &expiresStr}, nil, before, false},
		{"expires, objTs postdates expiry: rejected", Key{Expires: &expiresStr}, nil, after, true},
		{"expires, objTs equals expiry instant: accepted (not after)", Key{Expires: &expiresStr}, nil, t0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := KeyValid(tt.key, tt.revokedAt, tt.objTs)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDomainOf(t *testing.T) {
	tests := []struct{ principal, want string }{
		{"example.com", "example.com"},
		{"example.com#generate-invoice", "example.com"},
		{"a.b.example.com#x", "a.b.example.com"},
	}
	for _, tt := range tests {
		if got := DomainOf(tt.principal); got != tt.want {
			t.Errorf("DomainOf(%q) = %q, want %q", tt.principal, got, tt.want)
		}
	}
}
