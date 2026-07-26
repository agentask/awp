// Package awp is the AWP reference Go SDK: a thin client for sending
// envelopes and calling sync tools.
//
// "Thin" is deliberate: unlike cmd/awpd, this client keeps no on-disk
// state, runs no retry/outbox state machine, and does not receive
// envelopes on its own — it is for third-party Go programs that want to
// speak AWP directly (sign, send, verify) without running a daemon. Domain
// indexes are cached in memory for the lifetime of the Client only.
package awp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/manifest"
)

// Client is a thin AWP client, signing as (Domain, Kid, Priv). All methods
// are safe for concurrent use.
type Client struct {
	Domain string
	Kid    string
	Priv   ed25519.PrivateKey

	// HTTP is the client used for all outbound requests. Defaults to
	// http.DefaultClient if nil.
	HTTP *http.Client

	// IndexURL overrides where a domain's index is fetched from; nil uses
	// "https://" + domain + "/.well-known/awp.json". Override for
	// local/test use (e.g. pointing at an httptest.Server).
	IndexURL func(domain string) string

	mu    sync.Mutex
	cache map[string]*identity.Index
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) indexURL(domain string) string {
	if c.IndexURL != nil {
		return c.IndexURL(domain)
	}
	return "https://" + domain + "/.well-known/awp.json"
}

func (c *Client) keyID() string {
	return c.Domain + "/" + c.Kid
}

// FetchIndex resolves domain's signed index, caching it for the lifetime
// of the Client. The index's self-signature is verified (TOFU: the first
// fetch establishes trust in whichever key it names).
func (c *Client) FetchIndex(ctx context.Context, domain string) (*identity.Index, error) {
	c.mu.Lock()
	if idx, ok := c.cache[domain]; ok {
		c.mu.Unlock()
		return idx, nil
	}
	c.mu.Unlock()
	return c.fetchIndexUncached(ctx, domain)
}

// Refresh discards domain's cached index and re-fetches it, applying core
// §1.1 rotation-chain continuity would require the previous index — this
// SDK does not persist a rotation history across process runs, so Refresh
// simply re-fetches and re-trusts (TOFU) the new document. Long-running
// programs that need cross-restart continuity checking should use
// internal/keyresolver instead (it is available within this module tree)
// or track continuity themselves.
func (c *Client) Refresh(domain string) error {
	_, err := c.fetchIndexUncached(context.Background(), domain)
	return err
}

func (c *Client) fetchIndexUncached(ctx context.Context, domain string) (*identity.Index, error) {
	url := c.indexURL(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("awp: build index request for %s: %w", domain, err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("awp: fetch index %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("awp: read index %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("awp: fetch index %s: status %d", url, resp.StatusCode)
	}
	var idx identity.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, fmt.Errorf("awp: parse index for %s: %w", domain, err)
	}
	if err := idx.VerifySelfSig(); err != nil {
		return nil, fmt.Errorf("awp: %s index signature invalid: %w", domain, err)
	}

	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]*identity.Index{}
	}
	c.cache[domain] = &idx
	c.mu.Unlock()
	return &idx, nil
}

// Resolve implements httpsig.KeyResolver and delegation.KeyResolver: look
// up (domain, kid) in that domain's index, fetching it first if needed.
func (c *Client) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	idx, err := c.FetchIndex(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	for _, k := range idx.Keys {
		if k.Kid == kid {
			if k.Revoked {
				return nil, fmt.Errorf("awp: key %s/%s is revoked", domain, kid)
			}
			return k.PubKey()
		}
	}
	return nil, fmt.Errorf("awp: no key %s/%s in %s's index", domain, kid, domain)
}

// FetchManifest resolves principal's manifest via its domain's index,
// verifying its sha256 pin (core §1.2) and its own signature before
// returning it. Exported for callers that need a manifest without making
// a sync call against it — e.g. a caller that will fetch and run a
// `distribution.portable` tool locally instead of calling a hosted one
// (see examples/portable-wasm-tool).
func (c *Client) FetchManifest(ctx context.Context, principal string) (*manifest.Manifest, error) {
	idx, err := c.FetchIndex(ctx, identity.DomainOf(principal))
	if err != nil {
		return nil, fmt.Errorf("awp: resolve %s: %w", identity.DomainOf(principal), err)
	}
	return c.fetchManifest(ctx, idx, principal)
}

// fetchManifest is FetchManifest's implementation, reused by CallTool
// (which has already resolved idx and doesn't need to do so twice).
func (c *Client) fetchManifest(ctx context.Context, idx *identity.Index, principal string) (*manifest.Manifest, error) {
	var entry *identity.Entity
	for i := range idx.Entities {
		if idx.Entities[i].Name == principal {
			entry = &idx.Entities[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("awp: %s is not listed in %s's index", principal, identity.DomainOf(principal))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.Manifest, nil)
	if err != nil {
		return nil, fmt.Errorf("awp: build manifest request for %s: %w", principal, err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("awp: fetch manifest %s: %w", entry.Manifest, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("awp: read manifest %s: %w", entry.Manifest, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("awp: fetch manifest %s: status %d", entry.Manifest, resp.StatusCode)
	}
	if err := manifest.VerifyPinnedSha256(raw, entry.ManifestSha256); err != nil {
		return nil, fmt.Errorf("awp: manifest for %s: %w", principal, err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("awp: parse manifest for %s: %w", principal, err)
	}
	if m.Sig == nil {
		return nil, fmt.Errorf("awp: manifest for %s has no signature", principal)
	}
	pub, err := c.Resolve(identity.DomainOf(m.Name), m.Sig.Kid)
	if err != nil {
		return nil, fmt.Errorf("awp: resolve manifest signer for %s: %w", principal, err)
	}
	if err := m.Verify(pub); err != nil {
		return nil, fmt.Errorf("awp: manifest signature invalid for %s: %w", principal, err)
	}
	return &m, nil
}

// SendEnvelope builds, signs, and delivers an envelope directly to `to`'s
// resolved inbox. This is a single synchronous delivery attempt — no
// retry, no persistence; a caller wanting outbox semantics (backoff,
// dead-lettering, resumable delivery across process restarts) should run
// cmd/awpd instead of this SDK.
//
// ttl of 0 defaults to 3600s. inReplyTo may be nil.
func (c *Client) SendEnvelope(ctx context.Context, kind, to, thread string, inReplyTo *string, body json.RawMessage, ttl int) (*envelope.Envelope, error) {
	if ttl == 0 {
		ttl = 3600
	}
	e := &envelope.Envelope{
		Awp:       "0.1",
		ID:        envelope.NewID(),
		Kind:      kind,
		From:      c.Domain,
		To:        to,
		Thread:    thread,
		InReplyTo: inReplyTo,
		Ts:        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		TTL:       ttl,
		Body:      body,
	}
	if err := e.ValidateTTL(); err != nil {
		return nil, fmt.Errorf("awp: %w", err)
	}
	if err := e.Sign(c.Priv, c.Kid); err != nil {
		return nil, fmt.Errorf("awp: sign envelope: %w", err)
	}
	if err := e.ValidateSize(); err != nil {
		return nil, fmt.Errorf("awp: %w", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("awp: marshal envelope: %w", err)
	}

	domain := identity.DomainOf(to)
	idx, err := c.FetchIndex(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("awp: resolve %s: %w", domain, err)
	}
	if idx.Inbox == "" {
		return nil, fmt.Errorf("awp: %s declares no inbox", domain)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idx.Inbox, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("awp: build inbox request: %w", err)
	}
	req.Header.Set("Content-Type", "application/awp+json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("awp: deliver to %s: %w", idx.Inbox, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("awp: %s rejected envelope: status %d: %s", idx.Inbox, resp.StatusCode, respBody)
	}
	return e, nil
}

// CallOptions configures an optional sync-call session/delegation.
type CallOptions struct {
	// Session is a previously-issued AWP-Session token (core §1.3). Leave
	// empty for the first call to a stateful ("provider") tool.
	Session string
	// Delegation is a pre-built, pre-signed core §2.5 chain proving the
	// caller is acting on a delegator's behalf.
	Delegation []delegation.Link
}

// SessionInfo is a freshly-issued sync-call session, returned by a
// "provider"-state tool on a caller's first call (core §1.3).
type SessionInfo struct {
	Token   string `json:"token"`
	Sid     string `json:"sid"`
	Expires string `json:"expires"`
}

// CallTool resolves toolPrincipal's manifest, signs a sync HTTP call per
// awp-sig, and returns its output. If the provider signs its response
// (awp-sig §3, SHOULD), that signature is verified — a present-but-invalid
// response signature is treated as an error, per spec; an absent one is
// not.
func (c *Client) CallTool(ctx context.Context, toolPrincipal string, input json.RawMessage, opts CallOptions) (json.RawMessage, *SessionInfo, error) {
	domain := identity.DomainOf(toolPrincipal)
	idx, err := c.FetchIndex(ctx, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("awp: resolve %s: %w", domain, err)
	}
	m, err := c.fetchManifest(ctx, idx, toolPrincipal)
	if err != nil {
		return nil, nil, err
	}
	if m.Distribution.Hosted == nil {
		return nil, nil, fmt.Errorf("awp: %s has no hosted (sync) endpoint", toolPrincipal)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Distribution.Hosted.Endpoint, bytes.NewReader(input))
	if err != nil {
		return nil, nil, fmt.Errorf("awp: build tool call request: %w", err)
	}
	if opts.Session != "" {
		req.Header.Set("AWP-Session", opts.Session)
	}
	if len(opts.Delegation) > 0 {
		chainJSON, err := json.Marshal(opts.Delegation)
		if err != nil {
			return nil, nil, fmt.Errorf("awp: marshal delegation chain: %w", err)
		}
		req.Header.Set("AWP-Delegation", base64.RawURLEncoding.EncodeToString(chainJSON))
	}
	if err := httpsig.Sign(req, input, c.Priv, c.keyID(), time.Now()); err != nil {
		return nil, nil, fmt.Errorf("awp: sign tool call: %w", err)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("awp: call %s: %w", m.Distribution.Hosted.Endpoint, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("awp: read tool response: %w", err)
	}

	if verifyResult := httpsig.VerifyResponse(resp, respBody, time.Now(), c); verifyResult.Err != nil {
		return nil, nil, fmt.Errorf("awp: tool response signature invalid: %s: %s", verifyResult.Err.Code, verifyResult.Err.Detail)
	}

	if resp.StatusCode/100 != 2 {
		var errBody apperr.Body
		_ = json.Unmarshal(respBody, &errBody)
		if errBody.Error != nil {
			return nil, nil, fmt.Errorf("awp: tool call failed: %s: %s", errBody.Error.Code, errBody.Error.Detail)
		}
		return nil, nil, fmt.Errorf("awp: tool call failed: status %d: %s", resp.StatusCode, respBody)
	}

	var out struct {
		Output  json.RawMessage `json:"output,omitempty"`
		Session *SessionInfo    `json:"session,omitempty"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, nil, fmt.Errorf("awp: parse tool response: %w", err)
	}
	return out.Output, out.Session, nil
}

// SignDelegationLink builds and signs one core §2.5 delegation link with
// this Client as the delegator. nonce should be a fresh envelope.NewID()
// per link.
func (c *Client) SignDelegationLink(delegate string, scope delegation.Scope, expires time.Time, nonce string) (delegation.Link, error) {
	link := delegation.Link{
		Delegator: c.Domain,
		Delegate:  delegate,
		Scope:     scope,
		Expires:   expires.UTC().Format("2006-01-02T15:04:05.000Z"),
		Nonce:     nonce,
	}
	if err := link.Sign(c.Priv, c.Kid); err != nil {
		return delegation.Link{}, fmt.Errorf("awp: sign delegation link: %w", err)
	}
	return link, nil
}
