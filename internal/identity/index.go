package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Key is one entry of a domain index's keys[] array (core §1.1).
type Key struct {
	Kid     string  `json:"kid"`
	Alg     string  `json:"alg"`
	Pub     string  `json:"pub"` // base64url-raw-32-bytes, unpadded
	Created string  `json:"created"`
	Expires *string `json:"expires"`
	Revoked bool    `json:"revoked"`
	PrevSig *string `json:"prev_sig"`
}

// PubKey decodes the key's base64url raw public key bytes.
func (k Key) PubKey() (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(k.Pub)
	if err != nil {
		return nil, fmt.Errorf("identity: decode key %q pub: %w", k.Kid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: key %q pub has %d bytes, want %d", k.Kid, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Entity is one entry of a domain index's entities[] array (core §1.1).
type Entity struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Manifest       string `json:"manifest"`
	ManifestSha256 string `json:"manifest_sha256"`
}

// Transport is one entry of a domain index's transports[] array
// (core §1.1, awp-quic §2).
type Transport struct {
	Proto    string `json:"proto"`
	Endpoint string `json:"endpoint"`
}

// Index is the signed root document served at /.well-known/awp.json
// (core §1.1).
type Index struct {
	Awp          string      `json:"awp"`
	Domain       string      `json:"domain"`
	Updated      string      `json:"updated"`
	Keys         []Key       `json:"keys"`
	Entities     []Entity    `json:"entities"`
	Inbox        string      `json:"inbox"`
	Peers        []string    `json:"peers,omitempty"`
	Crawl        *bool       `json:"crawl,omitempty"`
	Transports   []Transport `json:"transports,omitempty"`
	Capabilities []string    `json:"capabilities,omitempty"`
	Sig          *Sig        `json:"sig,omitempty"`
}

// Sign attaches idx.Sig per core §0.1.
func (idx *Index) Sign(priv ed25519.PrivateKey, kid string) error {
	sig, err := Sign(idx, priv, kid)
	if err != nil {
		return err
	}
	idx.Sig = sig
	return nil
}

// VerifySelfSig verifies idx.Sig against one of idx.Keys identified by
// idx.Sig.Kid — the self-referential trust anchor for a domain index
// (core §1.1: "verified against a key in `keys`" via TOFU on first sight).
func (idx *Index) VerifySelfSig() error {
	if idx.Sig == nil {
		return errors.New("identity: index has no sig")
	}
	for _, k := range idx.Keys {
		if k.Kid == idx.Sig.Kid {
			pub, err := k.PubKey()
			if err != nil {
				return err
			}
			return VerifySig(idx, idx.Sig, pub)
		}
	}
	return fmt.Errorf("identity: index sig kid %q not found in keys", idx.Sig.Kid)
}

// ErrBrokenRotation identifies which link of a rotation chain failed.
type ErrBrokenRotation struct {
	Index  int
	Reason string
}

func (e *ErrBrokenRotation) Error() string {
	return fmt.Sprintf("identity: rotation chain broken at link %d: %s", e.Index, e.Reason)
}

// VerifyRotationChain verifies a sequence of keys representing successive
// generations of a domain's signing key, per core §1.1 rule 2: chain[0] is
// the trust anchor (a previously trusted key, taken on faith — e.g. via
// TOFU); for every i>0, chain[i].PrevSig MUST be the Ed25519 signature of
// chain[i].Pub's raw bytes by chain[i-1]'s key. Any broken link rejects with
// the offending index identified.
func VerifyRotationChain(chain []Key) error {
	if len(chain) == 0 {
		return errors.New("identity: empty rotation chain")
	}
	for i := 1; i < len(chain); i++ {
		prev := chain[i-1]
		cur := chain[i]
		prevPub, err := prev.PubKey()
		if err != nil {
			return &ErrBrokenRotation{Index: i, Reason: err.Error()}
		}
		curPub, err := cur.PubKey()
		if err != nil {
			return &ErrBrokenRotation{Index: i, Reason: err.Error()}
		}
		if cur.PrevSig == nil {
			return &ErrBrokenRotation{Index: i, Reason: "missing prev_sig"}
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(*cur.PrevSig)
		if err != nil {
			return &ErrBrokenRotation{Index: i, Reason: "prev_sig not valid base64url: " + err.Error()}
		}
		if !ed25519.Verify(prevPub, curPub, sigBytes) {
			return &ErrBrokenRotation{Index: i, Reason: "prev_sig does not verify against previous key"}
		}
	}
	return nil
}

// KeyValid reports whether key k may be used to verify a signature over an
// object timestamped objTs, applying core §1.1 rule 3 (revocation/expiry,
// postdates/predates).
//
// Spec gap, flagged per CLAUDE.md ("spec wins, discrepancy flagged"): the
// index schema in awp-core-v0.1.md §1.1 has no explicit "revoked_at" field,
// yet rule 3 requires comparing objTs against "the revocation" instant. We
// take revokedAt to be the `updated` timestamp of the index document that
// first set revoked:true (the caller's responsibility to track and supply);
// a nil revokedAt with Revoked=true is treated as "revocation instant
// unknown" and rejects unconditionally (fail closed).
func KeyValid(k Key, revokedAt *time.Time, objTs time.Time) error {
	if k.Revoked {
		if revokedAt == nil {
			return errors.New("identity: key revoked, revocation instant unknown (fail closed)")
		}
		if objTs.After(*revokedAt) {
			return errors.New("identity: signed object postdates key revocation")
		}
		// predates revocation: MAY be accepted (verifier policy) — we accept.
	}
	if k.Expires != nil {
		expTs, err := time.Parse(time.RFC3339, *k.Expires)
		if err != nil {
			return fmt.Errorf("identity: parse key expires: %w", err)
		}
		if objTs.After(expTs) {
			return errors.New("identity: signed object postdates key expiry")
		}
	}
	return nil
}
