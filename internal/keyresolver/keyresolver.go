// Package keyresolver implements a real HTTP-backed domain-index resolver:
// it fetches https://{domain}/.well-known/awp.json (core §1.1), verifies
// the index's self-signature, caches it via the awpd-store `keys_cache`
// bucket, and implements internal/inbox.KeyResolver (Resolve/Refresh) so it
// can be plugged directly into the receiver gate.
package keyresolver

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// ErrIdentityDiscontinuity means a freshly fetched index's active keys
// don't chain — either by being identical to, or by a valid core §1.1
// rule 2 rotation from — any key this resolver previously trusted for the
// domain. This is core §1.1's "a domain that loses all keys restarts with
// no continuity" case: it MUST NOT be silently accepted as an ordinary
// rotation (that would let a stolen or newly-generated key impersonate the
// domain to anyone who already trusted it). Resolve/Refresh both leave the
// prior trusted state untouched and return this error; only an explicit
// Reset call may accept the new key set as a new identity (TOFU reset,
// "surfaced to the operator, never silent" — Reset is that explicit,
// deliberate surfacing point).
var ErrIdentityDiscontinuity = errors.New("keyresolver: fetched index's keys do not chain from any previously trusted key for this domain (possible key loss or attack) — call Reset to accept it as a new identity")

// HTTPResolver resolves domain keys over HTTP.
type HTTPResolver struct {
	Client *http.Client
	Store  *store.Store
	Clock  clock.Clock
	// BaseURL maps a domain to the base URL its index is served from.
	// Production default is "https://" + domain; tests override this to
	// point at local httptest servers (there is no real DNS/WebPKI in a
	// unit test, and core §1.1 doesn't mandate one — it mandates HTTPS in
	// production, which is a deployment concern, not a protocol-logic one).
	BaseURL func(domain string) string
}

func (r *HTTPResolver) baseURL(domain string) string {
	if r.BaseURL != nil {
		return r.BaseURL(domain)
	}
	return "https://" + domain
}

func (r *HTTPResolver) clock() clock.Clock {
	if r.Clock != nil {
		return r.Clock
	}
	return clock.Real{}
}

func (r *HTTPResolver) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

// Resolve returns domain's currently trusted public key for kid, per core
// §0.1: fetch (or use the cached) index, find the key, reject if revoked.
func (r *HTTPResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	idx, err := r.load(domain, false)
	if err != nil {
		return nil, err
	}
	return keyFor(idx, domain, kid)
}

// Refresh forces a re-fetch — the core §0.1 "re-fetch the signer's index
// once on failure before hard-failing (rotation race)" primitive. It does
// NOT erase the previously trusted key set first: the re-fetched index
// still has to chain from whatever was trusted before (see
// ErrIdentityDiscontinuity). Refresh is a cache-invalidation retry, not a
// trust reset — those are deliberately different operations.
func (r *HTTPResolver) Refresh(domain string) error {
	_, err := r.load(domain, true)
	return err
}

// Reset discards domain's trusted key state entirely, so the next
// Resolve/Refresh treats the next fetched index as a first sighting
// (TOFU) rather than requiring rotation continuity from it. This is the
// explicit, deliberate action core §1.1 rule 2 requires when a domain's
// key history is legitimately broken (lost keys, operator-initiated
// re-bootstrap) — never triggered automatically by this package.
func (r *HTTPResolver) Reset(domain string) error {
	return r.Store.DeleteKeysCache(domain)
}

// ResolveInbox returns domain's advertised inbox URL (core §1.1: "inbox:
// ... Domain-level inbox is the default for all entities"), the primitive
// an outbox delivery sender needs to know where to POST.
func (r *HTTPResolver) ResolveInbox(domain string) (string, error) {
	idx, err := r.load(domain, false)
	if err != nil {
		return "", err
	}
	if idx.Inbox == "" {
		return "", fmt.Errorf("keyresolver: %s's index declares no inbox", domain)
	}
	return idx.Inbox, nil
}

// ResolveTransport returns domain's advertised endpoint for proto (e.g.
// "awp/1"), per core §1.1 / awp-quic §2. ok=false (with a nil error) means
// the domain's index doesn't advertise proto at all — per awp-quic §2,
// "Absence means HTTPS-only", not an error; callers (internal/quictrans's
// FallbackSender) MUST fall back to HTTPS rather than retry.
func (r *HTTPResolver) ResolveTransport(domain, proto string) (endpoint string, ok bool, err error) {
	idx, err := r.load(domain, false)
	if err != nil {
		return "", false, err
	}
	for _, t := range idx.Transports {
		if t.Proto == proto {
			return t.Endpoint, true, nil
		}
	}
	return "", false, nil
}

// ResolveWake returns domain's advertised wake endpoint (awp-push-v0.1.md
// §2), if any. ok=false (with a nil error) means the domain declares no
// `wake` field — absence, not an error; callers fall back to backoff-only
// retry with no wake hint at all.
func (r *HTTPResolver) ResolveWake(domain string) (endpoint string, ok bool, err error) {
	idx, err := r.load(domain, false)
	if err != nil {
		return "", false, err
	}
	if idx.Wake == nil || idx.Wake.Endpoint == "" {
		return "", false, nil
	}
	return idx.Wake.Endpoint, true, nil
}

func keyFor(idx *identity.Index, domain, kid string) (ed25519.PublicKey, error) {
	for _, k := range idx.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Revoked {
			return nil, fmt.Errorf("keyresolver: key %s/%s is revoked", domain, kid)
		}
		return k.PubKey()
	}
	return nil, fmt.Errorf("keyresolver: no key %q in %s's index", kid, domain)
}

func (r *HTTPResolver) load(domain string, force bool) (*identity.Index, error) {
	cachedIdx, cacheFound := r.cachedIndex(domain)
	if !force && cacheFound {
		return cachedIdx, nil
	}

	raw, err := r.fetch(domain)
	if err != nil {
		return nil, err
	}
	var idx identity.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("keyresolver: parse %s's index: %w", domain, err)
	}
	if err := idx.VerifySelfSig(); err != nil {
		return nil, fmt.Errorf("keyresolver: %s's index signature invalid: %w", domain, err)
	}

	// core §1.1 rule 2: a rotation is only trustworthy if it chains from a
	// key this resolver already trusted. A first-ever sighting (no prior
	// cache) is TOFU by definition — nothing to chain from yet.
	if cacheFound {
		if err := verifyContinuity(cachedIdx, &idx); err != nil {
			return nil, fmt.Errorf("keyresolver: %s: %w", domain, err)
		}
	}

	if err := r.Store.PutKeysCache(domain, raw, r.clock().Now(), ""); err != nil {
		return nil, err
	}
	return &idx, nil
}

func (r *HTTPResolver) cachedIndex(domain string) (*identity.Index, bool) {
	raw, found, err := r.Store.GetKeysCache(domain)
	if err != nil || !found {
		return nil, false
	}
	var idx identity.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, false // corrupt cache entry: treat as no prior trust
	}
	return &idx, true
}

// verifyContinuity checks that newIdx's active keys are either identical
// to, or a valid one-step core §1.1 rule 2 rotation from, some key in
// oldIdx — i.e. some key this resolver already trusted for the domain.
func verifyContinuity(oldIdx, newIdx *identity.Index) error {
	for _, newKey := range newIdx.Keys {
		if newKey.Revoked {
			continue
		}
		for _, oldKey := range oldIdx.Keys {
			if newKey.Kid == oldKey.Kid && newKey.Pub == oldKey.Pub {
				return nil // unchanged key, trivially continuous
			}
		}
	}
	for _, newKey := range newIdx.Keys {
		if newKey.Revoked {
			continue
		}
		for _, oldKey := range oldIdx.Keys {
			if identity.VerifyRotationChain([]identity.Key{oldKey, newKey}) == nil {
				return nil // valid rotation from a previously trusted key
			}
		}
	}
	return ErrIdentityDiscontinuity
}

func (r *HTTPResolver) fetch(domain string) ([]byte, error) {
	url := r.baseURL(domain) + "/.well-known/awp.json"
	resp, err := r.client().Get(url)
	if err != nil {
		return nil, fmt.Errorf("keyresolver: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyresolver: fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("keyresolver: read %s: %w", url, err)
	}
	return body, nil
}
