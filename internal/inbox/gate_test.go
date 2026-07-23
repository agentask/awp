package inbox

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/store"
)

const testFrom = "assistant.acme.com#scheduler"
const testDomain = "assistant.acme.com"
const testKid = "2026-07-01"

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

type fakeResolver struct {
	keys      map[string]ed25519.PublicKey
	refreshed []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{keys: map[string]ed25519.PublicKey{}}
}

func (f *fakeResolver) add(domain, kid string, pub ed25519.PublicKey) {
	f.keys[domain+"/"+kid] = pub
}

func (f *fakeResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := f.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}

func (f *fakeResolver) Refresh(domain string) error {
	f.refreshed = append(f.refreshed, domain)
	return nil
}

// rotatingResolver simulates a key-rotation race: Resolve returns the stale
// key until Refresh has been called once, then returns the current key.
type rotatingResolver struct {
	domain, kid    string
	stale, current ed25519.PublicKey
	refreshed      bool
	refreshCount   int
}

func (r *rotatingResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	if domain != r.domain || kid != r.kid {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	if r.refreshed {
		return r.current, nil
	}
	return r.stale, nil
}

func (r *rotatingResolver) Refresh(domain string) error {
	r.refreshCount++
	r.refreshed = true
	return nil
}

func newTestGate(t *testing.T, resolver KeyResolver, c clock.Clock) *Gate {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &Gate{Store: s, Keys: resolver, Clock: c}
}

// signedEnvelope builds a structurally valid, correctly signed envelope
// with the given ts/ttl, returning both the struct and its marshaled bytes.
func signedEnvelope(t *testing.T, priv ed25519.PrivateKey, ts time.Time, ttl int) (*envelope.Envelope, []byte) {
	t.Helper()
	e := &envelope.Envelope{
		Awp:    "0.1",
		ID:     envelope.NewID(),
		Kind:   "message",
		From:   testFrom,
		To:     "example.com#generate-invoice",
		Thread: envelope.NewID(),
		Ts:     ts.Format(time.RFC3339),
		TTL:    ttl,
		Body:   json.RawMessage(`{"type":"text","text":"hi"}`),
	}
	if err := e.Sign(priv, testKid); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return e, raw
}

// EARS gate 1: WHEN an envelope hits the gate, the system SHALL return the
// core §2.2 status for each failure class, IN GATE ORDER — this table
// includes combined-failure cases specifically to prove order, not just
// that each code is individually reachable.
func TestGate_OrderMatrix(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	_, wrongPriv := mustKeypair(t)

	newGate := func(t *testing.T) *Gate {
		r := newFakeResolver()
		r.add(testDomain, testKid, pub)
		return newTestGate(t, r, clock.NewFixed(now))
	}

	tests := []struct {
		name       string
		build      func(t *testing.T) []byte
		wantStatus int
		wantCode   string
	}{
		{
			name: "malformed JSON",
			build: func(t *testing.T) []byte {
				return []byte(`{not json`)
			},
			wantStatus: 400,
		},
		{
			name: "oversized payload (would also be structurally fine)",
			build: func(t *testing.T) []byte {
				_, raw := signedEnvelope(t, priv, now, 3600)
				pad := strings.Repeat("x", envelope.MaxSize)
				return append(raw[:len(raw)-1], []byte(`,"pad":"`+pad+`"}`)...)
			},
			wantStatus: 400,
		},
		{
			name: "ttl out of bounds (gate 1), even though ts is otherwise fine",
			build: func(t *testing.T) []byte {
				_, raw := signedEnvelope(t, priv, now, envelope.MinTTL) // sign first with valid ttl...
				// ...then hand-corrupt the ttl post-signature so gate 1's
				// structural check fires before any sig check would.
				var m map[string]any
				_ = json.Unmarshal(raw, &m)
				m["ttl"] = 1
				out, _ := json.Marshal(m)
				return out
			},
			wantStatus: 400,
		},
		{
			name: "missing sig",
			build: func(t *testing.T) []byte {
				e, _ := signedEnvelope(t, priv, now, 3600)
				e.Sig = nil
				raw, _ := json.Marshal(e)
				return raw
			},
			wantStatus: 400,
		},
		{
			name: "expired only: gate 2 fires",
			build: func(t *testing.T) []byte {
				_, raw := signedEnvelope(t, priv, now.Add(-2*time.Hour), 3600)
				return raw
			},
			wantStatus: 410,
		},
		{
			name: "expired AND bad signature: gate 2 fires first, never reaches gate 3",
			build: func(t *testing.T) []byte {
				e, _ := signedEnvelope(t, priv, now.Add(-2*time.Hour), 3600)
				e.Body = json.RawMessage(`{"type":"text","text":"tampered"}`) // invalidates sig too
				raw, _ := json.Marshal(e)
				return raw
			},
			wantStatus: 410, // not 401 — proves gate order
		},
		{
			name: "bad signature only: gate 3 fires",
			build: func(t *testing.T) []byte {
				e, _ := signedEnvelope(t, priv, now, 3600)
				e.Body = json.RawMessage(`{"type":"text","text":"tampered"}`)
				raw, _ := json.Marshal(e)
				return raw
			},
			wantStatus: 401,
		},
		{
			name: "signed by the wrong key entirely: gate 3 fires",
			build: func(t *testing.T) []byte {
				_, raw := signedEnvelope(t, wrongPriv, now, 3600)
				return raw
			},
			wantStatus: 401,
		},
		{
			name: "valid: gate 5 accepts a new envelope",
			build: func(t *testing.T) []byte {
				_, raw := signedEnvelope(t, priv, now, 3600)
				return raw
			},
			wantStatus: 202,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newGate(t)
			raw := tt.build(t)
			result := g.Accept(raw)
			if result.Status != tt.wantStatus {
				var detail string
				if result.Err != nil {
					detail = result.Err.Detail
				}
				t.Fatalf("status = %d, want %d (detail: %s)", result.Status, tt.wantStatus, detail)
			}
		})
	}
}

// bad signature + duplicate id: gate 3 must fire before gate 4 even though
// the id was already durably accepted once. This is the strongest order
// proof — it isolates gates 3 and 4 specifically.
func TestGate_BadSignatureBeatsDuplicateId(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	r := newFakeResolver()
	r.add(testDomain, testKid, pub)
	g := newTestGate(t, r, clock.NewFixed(now))

	e, raw := signedEnvelope(t, priv, now, 3600)
	first := g.Accept(raw)
	if first.Status != 202 {
		t.Fatalf("expected first accept to succeed with 202, got %d", first.Status)
	}

	// Same id, but tampered content (invalid signature).
	e.Body = json.RawMessage(`{"type":"text","text":"tampered"}`)
	tamperedRaw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second := g.Accept(tamperedRaw)
	if second.Status != 401 {
		t.Fatalf("expected 401 (gate 3 must fire before gate 4's dedupe hit), got %d", second.Status)
	}
}

// EARS gate 3: WHEN a duplicate id arrives on any transport, it SHALL be
// acked 200 and not reprocessed.
func TestGate_DuplicateIdAcked200NotReprocessed(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	r := newFakeResolver()
	r.add(testDomain, testKid, pub)
	g := newTestGate(t, r, clock.NewFixed(now))

	_, raw := signedEnvelope(t, priv, now, 3600)

	first := g.Accept(raw)
	if first.Status != 202 {
		t.Fatalf("expected first accept 202, got %d", first.Status)
	}

	for i := range 3 {
		dup := g.Accept(raw) // byte-identical resend, as the sender's outbox would retry
		if dup.Status != 200 {
			t.Fatalf("resend %d: expected 200, got %d", i, dup.Status)
		}
	}

	queued, err := g.Store.HasQueued(first.Envelope.ID)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if !queued {
		t.Fatal("expected envelope to remain queued exactly once")
	}
}

func TestGate_CapacityFailureReturns503(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	r := newFakeResolver()
	r.add(testDomain, testKid, pub)
	g := newTestGate(t, r, clock.NewFixed(now))

	_, raw := signedEnvelope(t, priv, now, 3600)

	// Force the durable-enqueue step to fail by closing the store out from
	// under the gate — simulating a capacity/storage failure at gate 5.
	if err := g.Store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	result := g.Accept(raw)
	if result.Status != 503 {
		t.Fatalf("expected 503, got %d", result.Status)
	}
	if result.Err == nil || !result.Err.Retryable {
		t.Fatalf("expected a retryable error, got %v", result.Err)
	}
}

// core §0.1: verifiers MUST re-fetch the signer's index once on failure
// before hard-failing (rotation race).
func TestGate_RotationRace_OneRefetchThenSucceed(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	stalePub, _ := mustKeypair(t)
	currentPub, currentPriv := mustKeypair(t)

	r := &rotatingResolver{domain: testDomain, kid: testKid, stale: stalePub, current: currentPub}
	g := newTestGate(t, r, clock.NewFixed(now))

	_, raw := signedEnvelope(t, currentPriv, now, 3600)
	result := g.Accept(raw)
	if result.Status != 202 {
		t.Fatalf("expected 202 after one refresh recovers the rotation race, got %d (err=%v)", result.Status, result.Err)
	}
	if r.refreshCount != 1 {
		t.Fatalf("expected exactly 1 refresh, got %d", r.refreshCount)
	}
}

func TestGate_RotationRace_StillFailsAfterRefetch(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	stalePub, _ := mustKeypair(t)
	_, wrongPriv := mustKeypair(t)

	// current == stale here: refresh doesn't actually fix anything, so the
	// signature (by an unrelated key) must still fail after the one retry.
	r := &rotatingResolver{domain: testDomain, kid: testKid, stale: stalePub, current: stalePub}
	g := newTestGate(t, r, clock.NewFixed(now))

	_, raw := signedEnvelope(t, wrongPriv, now, 3600)
	result := g.Accept(raw)
	if result.Status != 401 {
		t.Fatalf("expected 401, got %d", result.Status)
	}
	if r.refreshCount != 1 {
		t.Fatalf("expected exactly 1 refresh attempt before hard-fail, got %d", r.refreshCount)
	}
}
