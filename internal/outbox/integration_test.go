package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/inbox"
	"github.com/agentask/awp/internal/store"
)

// staticResolver is a KeyResolver that knows exactly one (domain, kid) ->
// pub mapping, standing in for a real domain-index fetch on the receiver
// side of these "two local instances" tests.
type staticResolver struct {
	domain string
	kid    string
	pub    ed25519.PublicKey
}

func (r *staticResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	if domain == r.domain && kid == r.kid {
		return r.pub, nil
	}
	return nil, fmt.Errorf("no key for %s/%s", domain, kid)
}

func (r *staticResolver) Refresh(string) error { return nil }

// urlTable is a mutable, concurrency-safe domain->URL map so a test can
// change what a domain resolves to mid-run — simulating a receiver going
// down and coming back up at a new address.
type urlTable struct {
	mu   sync.Mutex
	urls map[string]string
}

func newURLTable() *urlTable { return &urlTable{urls: map[string]string{}} }

func (t *urlTable) set(domain, url string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.urls[domain] = url
}

func (t *urlTable) resolve(domain string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	url, ok := t.urls[domain]
	if !ok {
		return "", fmt.Errorf("urlTable: no url for domain %q", domain)
	}
	return url, nil
}

// TestIntegration_RetriesWhileReceiverDownThenDeliversWhenUp is the
// CLAUDE.md Phase 3 gate scenario in miniature: two local instances (a
// sending outbox and a real internal/inbox.Gate receiver, both running in
// this process), with an induced failure (receiver unreachable) followed by
// recovery, asserted end-to-end through both stores.
func TestIntegration_RetriesWhileReceiverDownThenDeliversWhenUp(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)

	const receiverDomain = "receiver.example.com"
	receiverStore := openTestStore(t)
	receiverGate := &inbox.Gate{
		Store: receiverStore,
		Keys:  &staticResolver{domain: "assistant.acme.com", kid: "k1", pub: pub},
		Clock: clock.NewFixed(now),
	}

	senderStore := openTestStore(t)
	urls := newURLTable()
	urls.set(receiverDomain, "http://127.0.0.1:1") // nothing listens here: induced "receiver down"

	sender := &HTTPSender{
		Client:   &http.Client{Timeout: 2 * time.Second},
		InboxURL: urls.resolve,
	}

	_, raw := signedEnvelope(t, priv, "k1", receiverDomain+"#tool", now, 3600)
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := senderStore.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	fixedClock := clock.NewFixed(now)
	cfg := DefaultConfig()

	processed, err := ProcessDue(context.Background(), senderStore, fixedClock, sender, cfg, 10)
	if err != nil {
		t.Fatalf("ProcessDue (receiver down): %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected 1 attempt made while receiver is down, got %d", processed)
	}
	rec, found, err := senderStore.GetOutbox(env.ID)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v, found=%v", err, found)
	}
	if rec.State != store.StateQueued {
		t.Fatalf("expected record still queued (not delivered) while receiver is down, got %s", rec.State)
	}
	if rec.Attempts != 1 {
		t.Fatalf("expected 1 failed attempt recorded, got %d", rec.Attempts)
	}

	// Bring the receiver up as a second, independent local instance.
	server := httptest.NewServer(receiverGate)
	defer server.Close()
	urls.set(receiverDomain, server.URL)

	// Advance past the backoff window (attempts=1 caps well under 2s) and
	// the receiver's fixed clock in lockstep — both instances share "now."
	fixedClock.Advance(2 * time.Second)
	receiverGate.Clock = clock.NewFixed(now.Add(2 * time.Second))

	processed, err = ProcessDue(context.Background(), senderStore, fixedClock, sender, cfg, 10)
	if err != nil {
		t.Fatalf("ProcessDue (receiver up): %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected 1 delivered once the receiver is reachable, got %d", processed)
	}

	if _, found, _ := senderStore.GetOutbox(env.ID); found {
		t.Fatal("expected the outbox record to be gone (delivered) on the sender side")
	}
	queued, err := receiverStore.HasQueued(env.ID)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if !queued {
		t.Fatal("expected the receiver's own store to show the envelope accepted end-to-end")
	}
}

// TestIntegration_ReceiverRejectsNonRetryable4xx_DeadLetters exercises the
// other induced failure: a real receiver that rejects the envelope for a
// non-retryable reason (here, a signature it cannot verify because its
// resolver doesn't know the sender's key) — the outbox must dead-letter,
// not retry forever.
func TestIntegration_ReceiverRejectsNonRetryable4xx_DeadLetters(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)
	otherPub, _ := mustKeypair(t) // receiver trusts a DIFFERENT key entirely

	const receiverDomain = "strict-receiver.example.com"
	receiverStore := openTestStore(t)
	receiverGate := &inbox.Gate{
		Store: receiverStore,
		Keys:  &staticResolver{domain: "assistant.acme.com", kid: "k1", pub: otherPub},
		Clock: clock.NewFixed(now),
	}
	server := httptest.NewServer(receiverGate)
	defer server.Close()

	senderStore := openTestStore(t)
	urls := newURLTable()
	urls.set(receiverDomain, server.URL)
	sender := &HTTPSender{Client: &http.Client{Timeout: 2 * time.Second}, InboxURL: urls.resolve}

	_, raw := signedEnvelope(t, priv, "k1", receiverDomain+"#tool", now, 3600)
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := senderStore.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	processed, err := ProcessDue(context.Background(), senderStore, clock.NewFixed(now), sender, DefaultConfig(), 10)
	if err != nil {
		t.Fatalf("ProcessDue: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected 1 attempt made, got %d", processed)
	}

	dead, err := senderStore.ListDead()
	if err != nil {
		t.Fatalf("ListDead: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != env.ID {
		t.Fatalf("expected the rejected envelope to be dead-lettered, got %+v", dead)
	}
}
