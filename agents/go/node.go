// A minimal full AWP participant: serves a signed domain index, accepts
// envelopes at an inbox, and hands `message` envelopes to a callback. This
// is this demo's counterpart to internal/daemon.Daemon (Go) and
// pyawp/node.py (Python), scoped down to exactly what a demo agent needs.
//
// Simplified relative to the Go reference daemon in internal/daemon (see
// agents/go/README.md for the full list): the receiver gate below
// implements core §2.2's checks in the mandated order, but "durably
// enqueue" (step 5) means an in-memory goroutine, not a persisted queue
// that survives a restart — there is no internal/store here at all.
// `seen`-id dedupe is an in-memory map, not bbolt. Neither changes the wire
// behavior a peer observes; both mean this process's state is gone if it
// crashes, which internal/store is specifically built to survive.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	awp "github.com/agentask/awp/sdk/go"
)

// maxEnvelopeSize is core §2.1's serialized-envelope cap, enforced at the
// inbox gate before any parsing (envelope.MaxSize covers signed content;
// this is the same figure applied to the raw wire body).
const maxEnvelopeSize = 256 * 1024

// SendFunc lets a MessageHandler reply within the thread it was invoked
// for, without needing to know its own domain/thread bookkeeping.
type SendFunc func(ctx context.Context, kind string, body json.RawMessage) (*envelope.Envelope, error)

// MessageHandler processes one inbound `message` envelope.
type MessageHandler func(ctx context.Context, env *envelope.Envelope, send SendFunc)

// Node is a small in-memory (non-persistent) AWP participant: it holds an
// ed25519 identity, serves a signed index + inbox over plain HTTP, and
// dedupes/verifies inbound envelopes before handing `message` kinds to a
// MessageHandler. Mirrors agents/python/pyawp/node.py's Node.
type Node struct {
	Domain string
	Kid    string
	Priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey

	OnMessage MessageHandler

	client *awp.Client
	index  identity.Index

	mu   sync.Mutex
	seen map[string]time.Time // envelope id -> accept-until
}

// NewNode generates a fresh ed25519 identity and an unfinalized signed
// index (inbox left empty until Finalize is called, once the listen
// address is known).
func NewNode(domain, kid string) (*Node, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	n := &Node{
		Domain: domain,
		Kid:    kid,
		Priv:   priv,
		Pub:    pub,
		seen:   map[string]time.Time{},
	}
	n.index = identity.Index{
		Awp:     "0.1",
		Domain:  domain,
		Updated: nowRFC3339Milli(),
		Keys: []identity.Key{
			{Kid: kid, Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub), Created: nowRFC3339Milli()},
		},
		Inbox: "",
	}
	if err := n.index.Sign(priv, kid); err != nil {
		return nil, fmt.Errorf("sign initial index: %w", err)
	}
	return n, nil
}

// Finalize sets this node's advertised inbox URL and re-signs the index —
// call once its own reachable address is known, before any peer is
// expected to fetch /.well-known/awp.json. indexURL resolves a peer's
// domain to the base URL its index should be fetched from (the static-map
// DNS stand-in for these *.local demo domains).
func (n *Node) Finalize(inboxURL string, indexURL func(domain string) string) error {
	n.index.Inbox = inboxURL
	n.index.Updated = nowRFC3339Milli()
	if err := n.index.Sign(n.Priv, n.Kid); err != nil {
		return fmt.Errorf("sign finalized index: %w", err)
	}
	n.client = &awp.Client{
		Domain: n.Domain,
		Kid:    n.Kid,
		Priv:   n.Priv,
		HTTP:   http.DefaultClient,
		IndexURL: func(domain string) string {
			return indexURL(domain) + "/.well-known/awp.json"
		},
	}
	return nil
}

// Send delivers a signed envelope of the given kind directly to `to`'s
// resolved inbox via the SDK client. Call Finalize first.
func (n *Node) Send(ctx context.Context, kind, to, thread string, inReplyTo *string, body json.RawMessage) (*envelope.Envelope, error) {
	if n.client == nil {
		return nil, fmt.Errorf("node: Send called before Finalize")
	}
	return n.client.SendEnvelope(ctx, kind, to, thread, inReplyTo, body, 0)
}

// ServeHTTP implements the two AWP-facing endpoints: the signed index and
// the inbox. Mux'd manually rather than via http.ServeMux so this file has
// no dependency beyond net/http.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/awp.json":
		n.serveIndex(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/awp/inbox":
		n.serveInbox(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (n *Node) serveIndex(w http.ResponseWriter, _ *http.Request) {
	raw, err := json.Marshal(n.index)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func errorBody(code, detail string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"error": map[string]any{"code": code, "detail": detail, "retryable": false},
	})
	return raw
}

// serveInbox implements core §2.2's gate, in the mandated order:
//  1. parse (with size limit) -> 400
//  2. now <= ts + ttl -> 410
//  3. verify sig -> 401
//  4. dedupe on id -> 200 (already accepted, not reprocessed)
//  5. enqueue -> 202 (an in-memory goroutine here, not a durable queue —
//     see this file's package doc comment)
func (n *Node) serveInbox(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelopeSize+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errorBody("malformed", "read error: "+err.Error()))
		return
	}
	if len(raw) > maxEnvelopeSize {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errorBody("malformed", "envelope exceeds 256 KiB"))
		return
	}

	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errorBody("malformed", "parse error: "+err.Error()))
		return
	}

	ts, err := time.Parse("2006-01-02T15:04:05.000Z", env.Ts)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errorBody("malformed", "bad ts"))
		return
	}
	if time.Now().UTC().After(ts.Add(time.Duration(env.TTL) * time.Second)) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write(errorBody("expired", "envelope ttl expired"))
		return
	}

	if env.Sig == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(errorBody("unauthorized", "missing signature"))
		return
	}
	fromDomain := identity.DomainOf(env.From)
	pub, err := n.resolveWithRetry(r.Context(), fromDomain, env.Sig.Kid)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(errorBody("unauthorized", "resolve signer failed: "+err.Error()))
		return
	}
	if err := env.Verify(pub); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(errorBody("unauthorized", "signature verification failed: "+err.Error()))
		return
	}

	n.mu.Lock()
	now := time.Now()
	for id, until := range n.seen {
		if until.Before(now) {
			delete(n.seen, id)
		}
	}
	if until, ok := n.seen[env.ID]; ok && until.After(now) {
		n.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	n.seen[env.ID] = ts.Add(time.Duration(env.TTL) * time.Second)
	n.mu.Unlock()

	go n.process(&env)
	w.WriteHeader(http.StatusAccepted)
}

// resolveWithRetry implements core §0.1's rotation-race handling:
// verifiers MUST re-fetch the signer's index once on failure before
// hard-failing.
func (n *Node) resolveWithRetry(ctx context.Context, domain, kid string) (ed25519.PublicKey, error) {
	pub, err := n.client.Resolve(domain, kid)
	if err == nil {
		return pub, nil
	}
	if refreshErr := n.client.Refresh(domain); refreshErr != nil {
		return nil, err
	}
	return n.client.Resolve(domain, kid)
}

// process hands "content to respond to" envelopes to OnMessage. Per core
// §2.4, both `message` (opens/continues a thread unsolicited) and `reply`
// (a substantive response within one) carry content a participant should
// act on; `ack`/`close`/`error` do not. Judgment call, flagged here since
// it diverges from agents/python/pyawp/node.py's stricter `kind ==
// "message"` filter: that filter means the Python demo's *initiator*
// never actually reacts to the peer's replies on the thread it opened
// (concierge's replies land as kind=reply and are silently dropped by
// that gate) — a real gap in that reference, not a deliberate design this
// agent should copy, since this agent must correctly carry to completion
// both a thread it opens AND one opened against it.
func (n *Node) process(env *envelope.Envelope) {
	if n.OnMessage == nil {
		return
	}
	switch env.Kind {
	case "message", "reply":
	default:
		return
	}
	send := func(ctx context.Context, kind string, body json.RawMessage) (*envelope.Envelope, error) {
		return n.Send(ctx, kind, env.From, env.Thread, &env.ID, body)
	}
	n.OnMessage(context.Background(), env, send)
}

func nowRFC3339Milli() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}
