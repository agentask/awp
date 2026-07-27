// Package manifest implements the AWP core §1.2 entity manifest: types,
// signing, and sha256 content pinning against a domain index's
// entities[].manifest_sha256.
package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/agentask/awp/internal/identity"
)

// IOSchema holds the manifest's input/output JSON Schema pair (core §1.2).
type IOSchema struct {
	Input  json.RawMessage `json:"input,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
}

// Portable describes a wasm32-wasip1 stdio-json/1 distribution (core §1.2).
type Portable struct {
	URL          string   `json:"url"`
	Sha256       string   `json:"sha256"`
	Runtime      string   `json:"runtime"`
	Interface    string   `json:"interface"`
	Capabilities []string `json:"capabilities"`
}

// Hosted describes a sync HTTP distribution (core §1.2).
type Hosted struct {
	Endpoint string `json:"endpoint"`
}

// Distribution requires at least one of Hosted / Portable (core §1.2).
type Distribution struct {
	Hosted   *Hosted   `json:"hosted,omitempty"`
	Portable *Portable `json:"portable,omitempty"`
}

// Auth is the manifest's auth block; Sig is always "required" in v0.1.
type Auth struct {
	Sig    string   `json:"sig"`
	Scopes []string `json:"scopes,omitempty"`
}

// Manifest is one signed entity manifest document (core §1.2).
type Manifest struct {
	Awp          string          `json:"awp"`
	Name         string          `json:"name"`
	Kind         string          `json:"kind"`
	Version      string          `json:"version"`
	Updated      string          `json:"updated"`
	Description  string          `json:"description"`
	IO           IOSchema        `json:"io"`
	Distribution Distribution    `json:"distribution"`
	State        string          `json:"state"`
	Auth         Auth            `json:"auth"`
	Pricing      json.RawMessage `json:"pricing"`
	Inbox        *string         `json:"inbox"`
	// Environment is awp-capabilities-v0.1.md §2: absent or "production"
	// means production; "sandbox" marks the entity as safe to integrate
	// against with no real-world side effects (entity-specific what that
	// means, per its own Description).
	Environment string `json:"environment,omitempty"`
	// Capabilities is awp-capabilities-v0.1.md §3: entity-level feature
	// declarations. The only token that document defines is "dry-run" —
	// this entity honors the AWP-Dry-Run sync-call header.
	Capabilities []string      `json:"capabilities,omitempty"`
	Sig          *identity.Sig `json:"sig,omitempty"`
}

// DryRunCapability is the awp-capabilities-v0.1.md §3 token a manifest
// lists in Capabilities to declare it honors AWP-Dry-Run.
const DryRunCapability = "dry-run"

// EnvironmentSandbox is awp-capabilities-v0.1.md §2's non-production
// marker. EnvironmentProduction is the default and never needs to be set
// explicitly — Environment == "" means production.
const (
	EnvironmentSandbox    = "sandbox"
	EnvironmentProduction = "production"
)

// HasCapability reports whether m declares support for capability —
// e.g. manifest.HasCapability(manifest.DryRunCapability).
func (m *Manifest) HasCapability(capability string) bool {
	return slices.Contains(m.Capabilities, capability)
}

// Sign attaches m.Sig per core §0.1, signed by domainOf(m.Name)'s key.
func (m *Manifest) Sign(priv ed25519.PrivateKey, kid string) error {
	sig, err := identity.Sign(m, priv, kid)
	if err != nil {
		return err
	}
	m.Sig = sig
	return nil
}

// Verify checks m.Sig against pub. Callers resolve pub via
// (identity.DomainOf(m.Name), m.Sig.Kid) against the domain's index.
func (m *Manifest) Verify(pub ed25519.PublicKey) error {
	if m.Sig == nil {
		return fmt.Errorf("manifest: %q has no sig", m.Name)
	}
	return identity.VerifySig(m, m.Sig, pub)
}

// ErrPinMismatch is returned when a fetched manifest's content hash does
// not match the index's pinned entities[].manifest_sha256 (core §1.2: "a
// swapped manifest fails manifest_sha256 before its own signature is
// checked").
type ErrPinMismatch struct {
	Want string
	Got  string
}

func (e *ErrPinMismatch) Error() string {
	return fmt.Sprintf("manifest: sha256 pin mismatch: index pins %q, fetched document hashes to %q", e.Want, e.Got)
}

// VerifyPinnedSha256 checks the raw fetched manifest document bytes against
// the index-pinned hex sha256 digest. This MUST be checked before the
// manifest's own signature is verified (core §1.2).
func VerifyPinnedSha256(raw []byte, wantHex string) error {
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		return &ErrPinMismatch{Want: wantHex, Got: got}
	}
	return nil
}
