// Package keyresolver implements a real HTTP-backed domain-index resolver:
// it fetches https://{domain}/.well-known/awp.json (core §1.1), verifies
// the index's self-signature, caches it via the awpd-store `keys_cache`
// bucket, and implements internal/inbox.KeyResolver (Resolve/Refresh) so it
// can be plugged directly into the receiver gate.
package keyresolver

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

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

// Refresh evicts domain's cache entry and re-fetches — the core §0.1
// "re-fetch the signer's index once on failure before hard-failing
// (rotation race)" primitive (awpd-store §2: "Refresh(domain) ... deletes
// then re-fetches").
func (r *HTTPResolver) Refresh(domain string) error {
	if err := r.Store.DeleteKeysCache(domain); err != nil {
		return err
	}
	_, err := r.load(domain, true)
	return err
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
	if !force {
		if raw, found, err := r.Store.GetKeysCache(domain); err == nil && found {
			var idx identity.Index
			if err := json.Unmarshal(raw, &idx); err == nil {
				return &idx, nil
			}
			// Corrupt cache entry: fall through and re-fetch.
		}
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
	if err := r.Store.PutKeysCache(domain, raw, r.clock().Now(), ""); err != nil {
		return nil, err
	}
	return &idx, nil
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
