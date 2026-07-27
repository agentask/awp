package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

// TestNode_IndexRoundTripsAndSelfVerifies builds a Node's signed index,
// marshals it (as it would be served at /.well-known/awp.json),
// unmarshals it back (as a peer fetching it would), and checks the
// self-signature verifies — the Phase 1 EARS gate ("round-tripped
// sign->verify SHALL produce byte-identical JCS canon and verify"),
// applied to this demo agent's own index construction.
func TestNode_IndexRoundTripsAndSelfVerifies(t *testing.T) {
	n, err := NewNode("trip-planner.local", "k1")
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Finalize("http://127.0.0.1:8001/awp/inbox", func(d string) string { return "https://" + d }); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	raw, err := json.Marshal(n.index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	var idx identity.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	if err := idx.VerifySelfSig(); err != nil {
		t.Fatalf("VerifySelfSig: %v", err)
	}
	if idx.Domain != "trip-planner.local" {
		t.Fatalf("domain = %q", idx.Domain)
	}
	if idx.Inbox != "http://127.0.0.1:8001/awp/inbox" {
		t.Fatalf("inbox = %q", idx.Inbox)
	}
}

// peerFixture is a minimal signed identity for a fake sender, used to
// construct real signed envelopes without a full second Node.
type peerFixture struct {
	domain string
	kid    string
	priv   ed25519.PrivateKey
	index  identity.Index
	srv    *httptest.Server
}

func newPeerFixture(t *testing.T, domain string) *peerFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pf := &peerFixture{domain: domain, kid: "pk1", priv: priv}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	pf.index = identity.Index{
		Awp:     "0.1",
		Domain:  domain,
		Updated: now,
		Keys: []identity.Key{
			{Kid: pf.kid, Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub), Created: now},
		},
		Inbox: "",
	}
	if err := pf.index.Sign(priv, pf.kid); err != nil {
		t.Fatalf("sign peer index: %v", err)
	}
	pf.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := json.Marshal(pf.index)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(pf.srv.Close)
	return pf
}

func (pf *peerFixture) signedEnvelope(t *testing.T, to, thread string) *envelope.Envelope {
	t.Helper()
	e := &envelope.Envelope{
		Awp:    "0.1",
		ID:     envelope.NewID(),
		Kind:   "message",
		From:   pf.domain,
		To:     to,
		Thread: thread,
		Ts:     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		TTL:    3600,
		Body:   json.RawMessage(`{"type":"text","text":"hello from a fixture peer"}`),
	}
	if err := e.Sign(pf.priv, pf.kid); err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	return e
}

// setupReceivingNode builds a Node whose peer-index resolution points at
// pf's fake index server — the static-map DNS stand-in this whole demo
// uses for *.local domains.
func setupReceivingNode(t *testing.T, pf *peerFixture) (*Node, *httptest.Server) {
	t.Helper()
	n, err := NewNode("trip-planner.local", "k1")
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	recvSrv := httptest.NewServer(n)
	t.Cleanup(recvSrv.Close)

	indexURL := func(domain string) string {
		if domain == pf.domain {
			return pf.srv.URL
		}
		return "https://" + domain
	}
	if err := n.Finalize(recvSrv.URL+"/awp/inbox", indexURL); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return n, recvSrv
}

// TestInbox_AcceptsRealSignedEnvelope proves the inbox gate verifies a
// genuinely signed envelope (real ed25519 signature, real JCS canon via
// internal/identity + internal/envelope) and accepts it with 202.
func TestInbox_AcceptsRealSignedEnvelope(t *testing.T) {
	pf := newPeerFixture(t, "activities.local")
	n, recvSrv := setupReceivingNode(t, pf)
	n.OnMessage = func(_ context.Context, _ *envelope.Envelope, _ SendFunc) {}

	env := pf.signedEnvelope(t, n.Domain, envelope.NewID())
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	resp, err := http.Post(recvSrv.URL+"/awp/inbox", "application/awp+json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST inbox: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
}

// TestInbox_RejectsTamperedEnvelope proves a tampered (post-signing) body
// fails signature verification and is rejected with 401 — the receiving
// half of the Phase 1 EARS gate ("VerifySig rejects tampered content"),
// exercised over this demo's actual HTTP inbox handler.
func TestInbox_RejectsTamperedEnvelope(t *testing.T) {
	pf := newPeerFixture(t, "activities.local")
	_, recvSrv := setupReceivingNode(t, pf)

	env := pf.signedEnvelope(t, "trip-planner.local", envelope.NewID())
	env.Body = json.RawMessage(`{"type":"text","text":"tampered after signing"}`)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	resp, err := http.Post(recvSrv.URL+"/awp/inbox", "application/awp+json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST inbox: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestInbox_DedupesRepeatedID proves a duplicate id is acked 200 and not
// reprocessed (core §2.2 gate step 4).
func TestInbox_DedupesRepeatedID(t *testing.T) {
	pf := newPeerFixture(t, "activities.local")
	n, recvSrv := setupReceivingNode(t, pf)

	var callCount int
	n.OnMessage = func(_ context.Context, _ *envelope.Envelope, _ SendFunc) {
		callCount++
	}

	env := pf.signedEnvelope(t, n.Domain, envelope.NewID())
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	for i := 0; i < 2; i++ {
		resp, err := http.Post(recvSrv.URL+"/awp/inbox", "application/awp+json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("POST inbox #%d: %v", i, err)
		}
		defer resp.Body.Close()
		wantStatus := http.StatusAccepted
		if i == 1 {
			wantStatus = http.StatusOK
		}
		if resp.StatusCode != wantStatus {
			t.Fatalf("POST #%d status = %d, want %d", i, resp.StatusCode, wantStatus)
		}
	}

	// Give the background goroutine from the first accepted POST a moment
	// to run.
	time.Sleep(100 * time.Millisecond)
	if callCount != 1 {
		t.Fatalf("OnMessage called %d times, want 1", callCount)
	}
}
