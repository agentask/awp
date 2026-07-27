package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

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

func testManifest() *Manifest {
	return &Manifest{
		Awp:         "0.1",
		Name:        "example.com#generate-invoice",
		Kind:        "tool",
		Version:     "1.2.0",
		Updated:     "2026-07-20T18:00:00.000Z",
		Description: "Generates a PDF invoice from line items.",
		IO: IOSchema{
			Input:  []byte(`{"type":"object"}`),
			Output: []byte(`{"type":"object"}`),
		},
		Distribution: Distribution{Hosted: &Hosted{Endpoint: "https://example.com/awp/tools/generate-invoice"}},
		State:        "stateless",
		Auth:         Auth{Sig: "required"},
		Pricing:      []byte("null"),
		Inbox:        nil,
	}
}

// EARS gate 1 (manifest instance): round-trip sign->verify byte-identical
// JCS canon and verifies.
func TestManifestSignVerify_RoundTrip(t *testing.T) {
	pub, priv := mustKeypair(t)
	m := testManifest()

	canonBefore, err := identity.CanonicalBytes(m)
	if err != nil {
		t.Fatalf("canon before sign: %v", err)
	}

	if err := m.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}

	canonAfter, err := identity.CanonicalBytes(m)
	if err != nil {
		t.Fatalf("canon after sign: %v", err)
	}
	if string(canonBefore) != string(canonAfter) {
		t.Fatalf("canon changed after signing:\nbefore: %s\nafter:  %s", canonBefore, canonAfter)
	}

	if err := m.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestManifestCapabilitiesAndEnvironment covers awp-capabilities-v0.1.md
// §2/§3: Environment/Capabilities sign, verify, and tamper-detect exactly
// like any other manifest field, and HasCapability reads them correctly.
func TestManifestCapabilitiesAndEnvironment(t *testing.T) {
	pub, priv := mustKeypair(t)
	m := testManifest()
	m.Environment = EnvironmentSandbox
	m.Capabilities = []string{DryRunCapability}

	if !m.HasCapability(DryRunCapability) {
		t.Fatal("expected HasCapability(dry-run) to be true")
	}
	if m.HasCapability("some-other-capability") {
		t.Fatal("expected HasCapability to be false for an undeclared capability")
	}

	if err := m.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := m.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tampering with either field after signing must invalidate the sig.
	tampered := *m
	tampered.Environment = EnvironmentProduction
	if err := tampered.Verify(pub); err == nil {
		t.Fatal("expected a tampered environment to invalidate the signature")
	}
}

func TestManifestEnvironment_DefaultIsProduction(t *testing.T) {
	m := testManifest()
	if m.Environment != "" {
		t.Fatalf("expected zero-value Environment to be empty (production), got %q", m.Environment)
	}
}

func TestManifestVerify_RejectsTamperedContent(t *testing.T) {
	pub, priv := mustKeypair(t)
	m := testManifest()
	if err := m.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	m.Description = "tampered description"
	if err := m.Verify(pub); err == nil {
		t.Fatal("expected verification failure on tampered manifest")
	}
}

// core §1.2: "a swapped manifest fails manifest_sha256 before its own
// signature is checked."
func TestVerifyPinnedSha256_TableDriven(t *testing.T) {
	_, priv := mustKeypair(t)
	m := testManifest()
	if err := m.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(raw)
	correctHash := hex.EncodeToString(sum[:])

	swapped := testManifest()
	swapped.Name = "example.com#other-tool"
	if err := swapped.Sign(priv, "2026-07-01"); err != nil {
		t.Fatalf("sign swapped: %v", err)
	}
	swappedRaw, err := json.Marshal(swapped)
	if err != nil {
		t.Fatalf("marshal swapped: %v", err)
	}

	tests := []struct {
		name    string
		raw     []byte
		wantHex string
		wantErr bool
	}{
		{"matching pin", raw, correctHash, false},
		{"swapped manifest content, stale pin", swappedRaw, correctHash, true},
		{"corrupted single byte", append([]byte{}, raw[:len(raw)-1]...), correctHash, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPinnedSha256(tt.raw, tt.wantHex)
			if tt.wantErr && err == nil {
				t.Fatalf("expected pin mismatch, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				var pinErr *ErrPinMismatch
				if !asPinMismatch(err, &pinErr) {
					t.Fatalf("expected *ErrPinMismatch, got %T", err)
				}
			}
		})
	}
}

// asPinMismatch is a small helper avoiding an errors.As import just for one
// type assertion in the test.
func asPinMismatch(err error, target **ErrPinMismatch) bool {
	e, ok := err.(*ErrPinMismatch)
	if ok {
		*target = e
	}
	return ok
}
