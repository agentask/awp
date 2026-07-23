package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/store"
)

// domainTable maps a domain name to the real local base URL its
// httptest.Server ended up on — the DNS stand-in shared by both instances'
// resolvers in these tests.
type domainTable struct {
	mu sync.Mutex
	m  map[string]string
}

func newDomainTable() *domainTable { return &domainTable{m: map[string]string{}} }

func (t *domainTable) set(domain, base string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[domain] = base
}

func (t *domainTable) get(domain string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[domain]
}

// newTestInstance builds one real local AWP (HTTPS-only) instance: its own
// identity, store, Daemon, and a live httptest.Server — then finalizes its
// index with its own real (local) inbox URL and registers itself in table
// so the other instance's resolver can find it, exactly as DNS would in
// production. transports lets a test make this instance advertise (without
// necessarily backing) additional transports, e.g. a deliberately
// unreachable awp/1 endpoint for fallback testing; nil means HTTPS-only.
func newTestInstance(t *testing.T, domain, kid string, clk clock.Clock, table *domainTable, transports []identity.Transport) *Daemon {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), domain+".db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	resolver := &keyresolver.HTTPResolver{
		Store: st,
		Clock: clk,
		BaseURL: func(d string) string {
			return table.get(d)
		},
	}

	d, err := New(Config{
		Domain:   domain,
		Kid:      kid,
		Priv:     priv,
		Store:    st,
		Clock:    clk,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	table.set(domain, srv.URL)

	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", transports); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}
	return d
}

// drainOutbox repeatedly ticks the outbox until nothing remains due,
// bounded so a real bug (e.g. an infinite retry loop) fails the test
// instead of hanging it.
func drainOutbox(t *testing.T, ctx context.Context, d *Daemon) {
	t.Helper()
	for range 20 {
		due, err := d.Store.DueForDelivery(d.Clock.Now(), 100)
		if err != nil {
			t.Fatalf("DueForDelivery: %v", err)
		}
		if len(due) == 0 {
			return
		}
		if _, err := d.RunOutboxOnce(ctx); err != nil {
			t.Fatalf("RunOutboxOnce: %v", err)
		}
	}
	t.Fatal("drainOutbox: queue never emptied")
}

// drainInbound repeatedly claims+processes until the inbound queue is
// empty (a message's auto-reply enqueues more outbound work, not more
// inbound, so in practice one call suffices; looped defensively).
func drainInbound(t *testing.T, ctx context.Context, d *Daemon) {
	t.Helper()
	for range 20 {
		n, err := d.ProcessInboundOnce(ctx)
		if err != nil {
			t.Fatalf("ProcessInboundOnce: %v", err)
		}
		if n == 0 {
			return
		}
	}
	t.Fatal("drainInbound: queue never emptied")
}

// TestE2E_MessageAckReplyClose is the CLAUDE.md Phase 4 / v0.1.0-m1 release
// criterion: instance A sends `message` to instance B over HTTPS (modeled
// here as real HTTP over 127.0.0.1, per the same "two local instances"
// pattern used in Phases 2-3 — see docs/experiments.md for why no literal
// TLS/OS-process harness was built), completing
// message -> ack -> reply -> close with every signature verified and
// thread state correct on both sides.
func TestE2E_MessageAckReplyClose(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()

	a := newTestInstance(t, "a.example.com", "k1", clock.NewFixed(now), table, nil)
	b := newTestInstance(t, "b.example.com", "k1", clock.NewFixed(now), table, nil)

	threadID := envelope.NewID()
	msg, err := a.Send("message", "b.example.com", threadID, nil, json.RawMessage(`{"type":"text","text":"hello B"}`))
	if err != nil {
		t.Fatalf("A send message: %v", err)
	}

	drainOutbox(t, ctx, a)  // A delivers `message` to B's real inbox over HTTP
	drainInbound(t, ctx, b) // B processes it: records thread state, auto-sends ack+reply
	drainOutbox(t, ctx, b)  // B delivers ack and reply to A's real inbox
	drainInbound(t, ctx, a) // A processes ack+reply: records thread state, no further auto action

	closeEnv, err := a.Send("close", "b.example.com", threadID, nil, json.RawMessage(`{"type":"text","text":"bye"}`))
	if err != nil {
		t.Fatalf("A send close: %v", err)
	}
	drainOutbox(t, ctx, a)
	drainInbound(t, ctx, b)

	// --- thread state correct on both sides ---

	threadA, found, err := a.Store.GetThread(threadID)
	if err != nil || !found {
		t.Fatalf("A GetThread: %v found=%v", err, found)
	}
	if !threadA.Closed || threadA.ClosedBy != "a.example.com" {
		t.Fatalf("A's thread not correctly closed: %+v", threadA)
	}
	if threadA.Peer != "b.example.com" {
		t.Fatalf("A's thread peer should be b.example.com, got %q", threadA.Peer)
	}

	threadB, found, err := b.Store.GetThread(threadID)
	if err != nil || !found {
		t.Fatalf("B GetThread: %v found=%v", err, found)
	}
	if !threadB.Closed || threadB.ClosedBy != "a.example.com" {
		t.Fatalf("B's thread not correctly closed: %+v", threadB)
	}
	if threadB.Peer != "a.example.com" {
		t.Fatalf("B's thread peer should be a.example.com, got %q", threadB.Peer)
	}

	msgsA, err := a.Store.ThreadMessages(threadID)
	if err != nil {
		t.Fatalf("A ThreadMessages: %v", err)
	}
	msgsB, err := b.Store.ThreadMessages(threadID)
	if err != nil {
		t.Fatalf("B ThreadMessages: %v", err)
	}
	if len(msgsA) != 4 {
		t.Fatalf("expected 4 envelopes archived on A's side (message,ack,reply,close), got %d", len(msgsA))
	}
	if len(msgsB) != 4 {
		t.Fatalf("expected 4 envelopes archived on B's side, got %d", len(msgsB))
	}
	if msgsA[0].ID != msg.ID {
		t.Fatalf("A's first archived envelope should be the opening message")
	}
	if msgsA[3].ID != closeEnv.ID {
		t.Fatalf("A's last archived envelope should be the close")
	}
	wantKindsA := []string{"message", "ack", "reply", "close"}
	for i, m := range msgsA {
		var e envelope.Envelope
		if err := json.Unmarshal(m.Envelope, &e); err != nil {
			t.Fatalf("unmarshal archived envelope %d: %v", i, err)
		}
		if e.Kind != wantKindsA[i] {
			t.Fatalf("A's archived envelope %d: kind = %q, want %q", i, e.Kind, wantKindsA[i])
		}
	}

	// --- no dead letters anywhere: every hop's gate accepted every
	// envelope, which cannot happen unless every signature verified ---

	if deadA, err := a.Store.ListDead(); err != nil || len(deadA) != 0 {
		t.Fatalf("expected no dead letters on A, got %v (err=%v)", deadA, err)
	}
	if deadB, err := b.Store.ListDead(); err != nil || len(deadB) != 0 {
		t.Fatalf("expected no dead letters on B, got %v (err=%v)", deadB, err)
	}

	// --- explicit re-verification: independently re-derive each signer's
	// key via a fresh resolver and re-check every archived envelope's
	// signature, rather than inferring "it must have verified" from the
	// absence of dead letters alone ---

	verifyResolver := newVerifyResolver(t, table)
	for _, m := range msgsA {
		verifyEnvelopeSignature(t, verifyResolver, m.Envelope)
	}
	for _, m := range msgsB {
		verifyEnvelopeSignature(t, verifyResolver, m.Envelope)
	}
}

func newVerifyResolver(t *testing.T, table *domainTable) *keyresolver.HTTPResolver {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "verify.db"))
	if err != nil {
		t.Fatalf("open verify store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &keyresolver.HTTPResolver{
		Store: st,
		Clock: clock.Real{},
		BaseURL: func(d string) string {
			return table.get(d)
		},
	}
}

// verifyEnvelopeSignature re-resolves env's signer key via resolver and
// checks the signature independently of any prior gate outcome.
func verifyEnvelopeSignature(t *testing.T, resolver *keyresolver.HTTPResolver, raw []byte) {
	t.Helper()
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal archived envelope: %v", err)
	}
	if env.Sig == nil {
		t.Fatalf("archived envelope %s has no sig", env.ID)
	}
	pub, err := resolver.Resolve(identity.DomainOf(env.From), env.Sig.Kid)
	if err != nil {
		t.Fatalf("resolve signer key for %s: %v", env.ID, err)
	}
	if err := env.Verify(pub); err != nil {
		t.Fatalf("signature verification failed for archived envelope %s: %v", env.ID, err)
	}
}
