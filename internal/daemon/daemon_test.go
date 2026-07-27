package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/store"
)

// noopResolver satisfies Resolver without any network calls, for tests that
// exercise Send/ProcessInboundOnce directly and never need to actually
// deliver or verify a peer's signature.
type noopResolver struct{}

func (noopResolver) Resolve(string, string) (ed25519.PublicKey, error) { return nil, nil }
func (noopResolver) Refresh(string) error                              { return nil }
func (noopResolver) ResolveInbox(string) (string, error)               { return "", nil }
func (noopResolver) ResolveTransport(string, string) (string, bool, error) {
	return "", false, nil
}

func newUnitTestDaemon(t *testing.T, domain string, clk clock.Clock) *Daemon {
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
	d, err := New(Config{Domain: domain, Kid: "k1", Priv: priv, Store: st, Clock: clk, Resolver: noopResolver{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestSend_RecordsThreadStateAndEnqueuesOutbound(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newUnitTestDaemon(t, "a.example.com", clock.NewFixed(now))

	thread := envelope.NewID()
	e, err := d.Send("message", "b.example.com", thread, nil, json.RawMessage(`{"type":"text","text":"hi"}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if e.From != "a.example.com" || e.To != "b.example.com" || e.Kind != "message" {
		t.Fatalf("unexpected envelope: %+v", e)
	}
	if e.Sig == nil {
		t.Fatal("expected the outbound envelope to be signed")
	}

	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 1 || due[0].ID != e.ID {
		t.Fatalf("expected the sent envelope to be enqueued for delivery, got %+v", due)
	}

	th, found, err := d.Store.GetThread(thread)
	if err != nil || !found {
		t.Fatalf("GetThread: %v found=%v", err, found)
	}
	if th.Peer != "b.example.com" || th.Closed {
		t.Fatalf("unexpected thread state: %+v", th)
	}
}

func TestSend_CloseMarksOwnThreadClosedImmediately(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newUnitTestDaemon(t, "a.example.com", clock.NewFixed(now))
	thread := envelope.NewID()

	if _, err := d.Send("message", "b.example.com", thread, nil, json.RawMessage(`{"type":"text","text":"hi"}`)); err != nil {
		t.Fatalf("Send message: %v", err)
	}
	if _, err := d.Send("close", "b.example.com", thread, nil, json.RawMessage(`{"type":"text","text":"bye"}`)); err != nil {
		t.Fatalf("Send close: %v", err)
	}

	th, found, err := d.Store.GetThread(thread)
	if err != nil || !found {
		t.Fatalf("GetThread: %v found=%v", err, found)
	}
	if !th.Closed || th.ClosedBy != "a.example.com" {
		t.Fatalf("expected sender-side close to mark the thread closed immediately, got %+v", th)
	}
}

// injectInbound signs+accepts an envelope directly into d's inbound queue,
// bypassing HTTP — used to unit-test ProcessInboundOnce's handling logic in
// isolation from delivery/transport concerns (already covered elsewhere).
func injectInbound(t *testing.T, d *Daemon, from, kind, thread string, inReplyTo *string, body json.RawMessage, ts time.Time) *envelope.Envelope {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	e := &envelope.Envelope{
		Awp: "0.1", ID: envelope.NewID(), Kind: kind,
		From: from, To: d.Domain, Thread: thread, InReplyTo: inReplyTo,
		Ts: ts.UTC().Format(RFC3339Milli), TTL: DefaultTTL, Body: body,
	}
	if err := e.Sign(priv, "ext-k1"); err != nil {
		t.Fatalf("sign injected envelope: %v", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal injected envelope: %v", err)
	}
	if _, err := d.Store.AcceptInbound(e.ID, ts.Add(time.Duration(e.TTL)*time.Second), raw); err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}
	return e
}

func TestProcessInboundOnce_MessageTriggersAckThenReply(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newUnitTestDaemon(t, "b.example.com", clock.NewFixed(now))
	thread := envelope.NewID()

	msg := injectInbound(t, d, "a.example.com", "message", thread, nil, json.RawMessage(`{"type":"text","text":"hi"}`), now)

	n, err := d.ProcessInboundOnce(context.Background())
	if err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 processed, got %d", n)
	}

	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("expected 2 outbound envelopes enqueued (ack, reply), got %d", len(due))
	}

	var kinds, inReplyTos []string
	for _, rec := range due {
		var e envelope.Envelope
		if err := json.Unmarshal(rec.Envelope, &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		kinds = append(kinds, e.Kind)
		if e.InReplyTo == nil {
			t.Fatalf("expected in_reply_to set on the auto-response, got nil")
		}
		inReplyTos = append(inReplyTos, *e.InReplyTo)
		if e.To != "a.example.com" {
			t.Fatalf("expected auto-response addressed back to the sender, got %q", e.To)
		}
	}
	if !(slices.Contains(kinds, "ack") && slices.Contains(kinds, "reply")) {
		t.Fatalf("expected both ack and reply enqueued, got kinds=%v", kinds)
	}
	for _, id := range inReplyTos {
		if id != msg.ID {
			t.Fatalf("expected in_reply_to=%s, got %s", msg.ID, id)
		}
	}
}

func TestProcessInboundOnce_CustomMessageHandlerReplacesDefault(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "b.example.com.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var gotEnv *envelope.Envelope
	handler := func(_ context.Context, env *envelope.Envelope, send SendFunc) error {
		gotEnv = env
		_, err := send("reply", json.RawMessage(`{"type":"text","text":"custom handled"}`))
		return err
	}

	d, err := New(Config{
		Domain: "b.example.com", Kid: "k1", Priv: priv, Store: st,
		Clock: clock.NewFixed(now), Resolver: noopResolver{}, MessageHandler: handler,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	thread := envelope.NewID()
	msg := injectInbound(t, d, "a.example.com", "message", thread, nil, json.RawMessage(`{"type":"text","text":"hi"}`), now)

	n, err := d.ProcessInboundOnce(context.Background())
	if err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 processed, got %d", n)
	}
	if gotEnv == nil || gotEnv.ID != msg.ID {
		t.Fatalf("expected the custom handler to be invoked with the inbound message, got %+v", gotEnv)
	}

	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	// Exactly the custom handler's one send — no default ack additionally
	// enqueued alongside it.
	if len(due) != 1 {
		t.Fatalf("expected exactly 1 outbound envelope from the custom handler, got %d", len(due))
	}
	var e envelope.Envelope
	if err := json.Unmarshal(due[0].Envelope, &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Kind != "reply" || string(e.Body) != `{"type":"text","text":"custom handled"}` {
		t.Fatalf("unexpected envelope from custom handler: %+v", e)
	}
	if e.To != "a.example.com" || e.Thread != thread || e.InReplyTo == nil || *e.InReplyTo != msg.ID {
		t.Fatalf("expected send() to pre-bind to/thread/in_reply_to from the inbound message, got %+v", e)
	}
}

func TestProcessInboundOnce_NonMessageKindsRecordButDoNotAutoRespond(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newUnitTestDaemon(t, "a.example.com", clock.NewFixed(now))
	thread := envelope.NewID()

	// Establish the thread as if A had sent the opener itself.
	if _, err := d.Send("message", "b.example.com", thread, nil, json.RawMessage(`{"type":"text","text":"hi"}`)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	injectInbound(t, d, "b.example.com", "reply", thread, nil, json.RawMessage(`{"type":"text","text":"ok"}`), now)

	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}

	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	// Only A's original message remains queued; the inbound reply must not
	// have triggered any further auto-response.
	if len(due) != 1 {
		t.Fatalf("expected no auto-response to a `reply`, got %d outbound records", len(due))
	}
}

func TestRunGCOnce_DeletesExpiredSeenAndPastRetentionDeadLetters(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	fixed := clock.NewFixed(now)
	d := newUnitTestDaemon(t, "a.example.com", fixed)
	d.DeadRetention = 24 * time.Hour

	expiredSeenID := envelope.NewID()
	if _, err := d.Store.AcceptInbound(expiredSeenID, now.Add(-time.Hour), []byte("{}")); err != nil {
		t.Fatalf("AcceptInbound: %v", err)
	}

	deadID := envelope.NewID()
	if err := d.Store.EnqueueOutbound(deadID, []byte("{}"), now); err != nil {
		t.Fatalf("EnqueueOutbound: %v", err)
	}
	if err := d.Store.MarkDead(deadID, "expired", "ttl", now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("MarkDead: %v", err)
	}

	seenDeleted, deadDeleted, err := d.RunGCOnce()
	if err != nil {
		t.Fatalf("RunGCOnce: %v", err)
	}
	if seenDeleted != 1 {
		t.Fatalf("expected 1 seen entry deleted, got %d", seenDeleted)
	}
	if deadDeleted != 1 {
		t.Fatalf("expected 1 dead letter deleted, got %d", deadDeleted)
	}

	if _, found, _ := d.Store.GetOutbox(deadID); found {
		t.Fatal("expected the past-retention dead letter to be gone")
	}
}

func TestNew_DeadRetentionDefaultsWhenUnset(t *testing.T) {
	d := newUnitTestDaemon(t, "a.example.com", clock.NewFixed(time.Now()))
	if d.DeadRetention != DefaultDeadRetention {
		t.Fatalf("expected DeadRetention to default to %v, got %v", DefaultDeadRetention, d.DeadRetention)
	}
}
