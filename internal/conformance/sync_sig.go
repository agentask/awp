package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/manifest"
)

// checkResponseSigning is deliberately outside the core §5 / awp-quic §8
// checklists this package otherwise implements: awp-sig §3 response
// signing is a SHOULD, with no checklist item of its own in either spec
// document. It exists because internal/httpsig gained SignResponse and
// VerifyResponse with no conformance coverage at all — a domain could
// sign every response wrong and nothing in this CLI would ever notice.
// Absence is not a failure (SHOULD, not MUST); a present-but-invalid
// signature is.
func checkResponseSigning(ctx context.Context, opts Options, idx *identity.Index) CheckResult {
	const id = "awp-sig-3-response-signing"
	const desc = "If a sync response carries Signature-Input (awp-sig §3, SHOULD), it verifies; a present-but-invalid response signature is rejected."

	if opts.CallerPriv == nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "requires -key/-kid to sign a sync call"}
	}

	principal, endpoint, err := findHostedEntity(ctx, opts, idx, "tool")
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "could not resolve a callable tool to probe: " + err.Error()}
	}
	if endpoint == "" {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "domain publishes no kind:tool entity with a hosted endpoint to probe"}
	}

	body := []byte(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	keyID := opts.CallerDomain + "/" + opts.CallerKid
	if err := httpsig.Sign(req, body, opts.CallerPriv, keyID, opts.now()); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "sign probe request: " + err.Error()}
	}

	resp, err := opts.client().Do(req)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}

	result := httpsig.VerifyResponse(resp, respBody, opts.now(), indexKeyResolver{idx: idx})
	if result.Err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fmt.Sprintf("%s: %s", result.Err.Code, result.Err.Detail)}
	}
	if !result.Signed {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: fmt.Sprintf("%s did not sign its response (SHOULD, not MUST) — nothing to verify", principal)}
	}
	return CheckResult{ID: id, Description: desc, Status: Pass, Detail: "verified response signature from " + principal}
}

// checkStatusEntity is, like checkResponseSigning, outside the core §5 /
// awp-quic §8 checklists — awp-kinds-v0.1.md §2 registers `status` as an
// entity kind, not a core checklist item. Skips (not fails) when there's
// nothing to probe: a domain with no kind:status entity hasn't done
// anything wrong, it just hasn't adopted this optional registration.
func checkStatusEntity(ctx context.Context, opts Options, idx *identity.Index) CheckResult {
	const id = "awp-kinds-2-status-entity"
	const desc = "A kind:status entity, if present, responds with a conforming {healthy, checked_at} shape (awp-kinds-v0.1.md §2)."

	if opts.CallerPriv == nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "requires -key/-kid to sign a sync call"}
	}

	principal, endpoint, err := findHostedEntity(ctx, opts, idx, "status")
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "could not resolve a kind:status entity to probe: " + err.Error()}
	}
	if endpoint == "" {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "domain publishes no kind:status entity"}
	}

	body := []byte(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	keyID := opts.CallerDomain + "/" + opts.CallerKid
	if err := httpsig.Sign(req, body, opts.CallerPriv, keyID, opts.now()); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "sign probe request: " + err.Error()}
	}

	resp, err := opts.client().Do(req)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	if resp.StatusCode/100 != 2 {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fmt.Sprintf("%s: status %d: %s", principal, resp.StatusCode, respBody)}
	}

	var out struct {
		Output struct {
			Healthy   *bool  `json:"healthy"`
			CheckedAt string `json:"checked_at"`
		} `json:"output"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "unparseable response: " + err.Error()}
	}
	if out.Output.Healthy == nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "response has no boolean \"healthy\" field"}
	}
	if _, err := time.Parse(time.RFC3339, out.Output.CheckedAt); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "\"checked_at\" is not a valid RFC 3339 timestamp: " + err.Error()}
	}
	return CheckResult{ID: id, Description: desc, Status: Pass, Detail: fmt.Sprintf("%s reports healthy=%v as of %s", principal, *out.Output.Healthy, out.Output.CheckedAt)}
}

// findHostedEntity looks for the first entity of kind wantKind in idx
// whose manifest verifies (sha256 pin, then signature) and declares a
// hosted distribution, returning its principal and endpoint. ("", "",
// nil) means none was found — not itself an error.
func findHostedEntity(ctx context.Context, opts Options, idx *identity.Index, wantKind string) (principal, endpoint string, err error) {
	for _, entry := range idx.Entities {
		if entry.Kind != wantKind {
			continue
		}
		m, ferr := fetchAndVerifyManifest(ctx, opts, idx, entry.Manifest, entry.ManifestSha256)
		if ferr != nil {
			continue // try the next candidate; one broken entity shouldn't sink the check
		}
		if m.Distribution.Hosted != nil && m.Distribution.Hosted.Endpoint != "" {
			return entry.Name, m.Distribution.Hosted.Endpoint, nil
		}
	}
	return "", "", nil
}

func fetchAndVerifyManifest(ctx context.Context, opts Options, idx *identity.Index, url, wantSha256Hex string) (*manifest.Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := manifest.VerifyPinnedSha256(raw, wantSha256Hex); err != nil {
		return nil, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Sig == nil {
		return nil, fmt.Errorf("manifest has no signature")
	}
	pub, err := indexKeyResolver{idx: idx}.Resolve(identity.DomainOf(m.Name), m.Sig.Kid)
	if err != nil {
		return nil, err
	}
	if err := m.Verify(pub); err != nil {
		return nil, err
	}
	return &m, nil
}

// indexKeyResolver resolves keys against an already-fetched-and-verified
// index for its own domain — sufficient here since every key this
// package's checks need (a manifest's signer, a sync response's signer)
// belongs to the one domain under test, not some third party.
type indexKeyResolver struct{ idx *identity.Index }

func (r indexKeyResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	if domain != r.idx.Domain {
		return nil, fmt.Errorf("indexKeyResolver: %s is not the domain under test (%s)", domain, r.idx.Domain)
	}
	for _, k := range r.idx.Keys {
		if k.Kid == kid {
			if k.Revoked {
				return nil, fmt.Errorf("key %s/%s is revoked", domain, kid)
			}
			return k.PubKey()
		}
	}
	return nil, fmt.Errorf("no key %s/%s in index", domain, kid)
}

func (r indexKeyResolver) Refresh(string) error { return nil }
