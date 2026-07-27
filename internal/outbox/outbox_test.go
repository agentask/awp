package outbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/store"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// signedEnvelope builds and signs a valid envelope addressed to "to", and
// returns both the struct and its marshaled bytes.
func signedEnvelope(t *testing.T, priv ed25519.PrivateKey, kid, to string, ts time.Time, ttl int) (*envelope.Envelope, []byte) {
	t.Helper()
	e := &envelope.Envelope{
		Awp:    "0.1",
		ID:     envelope.NewID(),
		Kind:   "message",
		From:   "assistant.acme.com#scheduler",
		To:     to,
		Thread: envelope.NewID(),
		Ts:     ts.Format(time.RFC3339),
		TTL:    ttl,
		Body:   json.RawMessage(`{"type":"text","text":"hi"}`),
	}
	if err := e.Sign(priv, kid); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return e, raw
}

// fakeSender is a scripted Sender: each call consumes the next scripted
// response (or repeats the last one if the script is shorter than the call
// count). It also records every raw payload it was asked to send, so tests
// can assert rule 4 ("same bytes every attempt").
type fakeSender struct {
	mu        sync.Mutex
	responses []fakeResponse
	calls     int
	sentRaw   [][]byte
}

type fakeResponse struct {
	status        int
	retryAfter    time.Duration
	hasRetryAfter bool
	err           error
}

func (f *fakeSender) Send(_ context.Context, _ string, raw []byte) (int, time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentRaw = append(f.sentRaw, append([]byte{}, raw...))
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	r := f.responses[i]
	return r.status, r.retryAfter, r.hasRetryAfter, r.err
}

// wakeSender embeds fakeSender and additionally implements WakeNotifier,
// recording every domain it was asked to wake.
type wakeSender struct {
	fakeSender
	woken []string
}

func (w *wakeSender) NotifyWake(_ context.Context, domain string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.woken = append(w.woken, domain)
}

// TestAttempt_WakeNotifier_FiresOnUnreachableOnly covers awp-push-v0.1.md
// §3: NotifyWake fires on network error / 5xx / unhonored-429, and never
// on 2xx, dead-lettered 4xx, or an honored 429 (the receiver just proved
// it's alive).
func TestAttempt_WakeNotifier_FiresOnUnreachableOnly(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	tests := []struct {
		name     string
		response fakeResponse
		wantWake bool
	}{
		{"2xx delivered: no wake", fakeResponse{status: 200}, false},
		{"network failure: wake", fakeResponse{err: errors.New("connection refused")}, true},
		{"5xx: wake", fakeResponse{status: 503}, true},
		{"429 without Retry-After treated as 5xx: wake", fakeResponse{status: 429}, true},
		{"429 with Retry-After honored: no wake (receiver is alive)", fakeResponse{status: 429, retryAfter: 5 * time.Second, hasRetryAfter: true}, false},
		{"non-429 4xx dead-letters: no wake", fakeResponse{status: 403}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openTestStore(t)
			_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, 3600)
			var env envelope.Envelope
			_ = json.Unmarshal(raw, &env)
			if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
				t.Fatalf("enqueue: %v", err)
			}
			rec, _, _ := st.GetOutbox(env.ID)

			sender := &wakeSender{fakeSender: fakeSender{responses: []fakeResponse{tt.response}}}
			if _, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), rec); err != nil {
				t.Fatalf("Attempt: %v", err)
			}

			gotWake := len(sender.woken) > 0
			if gotWake != tt.wantWake {
				t.Fatalf("wake fired = %v, want %v (woken=%v)", gotWake, tt.wantWake, sender.woken)
			}
			if gotWake && sender.woken[0] != "example.com" {
				t.Fatalf("expected wake for domain example.com, got %q", sender.woken[0])
			}
		})
	}
}

// TestAttempt_PlainSender_NoWakeNotifier confirms a Sender that doesn't
// implement WakeNotifier (every existing Sender before this feature) is
// unaffected — Attempt's type assertion must not panic or require it.
func TestAttempt_PlainSender_NoWakeNotifier(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, 3600)
	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)
	if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rec, _, _ := st.GetOutbox(env.ID)

	sender := &fakeSender{responses: []fakeResponse{{err: errors.New("down")}}}
	if _, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), rec); err != nil {
		t.Fatalf("Attempt: %v", err)
	}
}

func TestFullJitterBackoff_StaysWithinBounds(t *testing.T) {
	base := time.Second
	cap := 300 * time.Second
	for attempts := range 15 {
		for range 200 {
			d := fullJitterBackoff(base, cap, attempts)
			want := base * time.Duration(int64(1)<<min(attempts, 32))
			if want > cap || want <= 0 {
				want = cap
			}
			if d < 0 || d > want {
				t.Fatalf("attempts=%d: backoff %v outside [0, %v]", attempts, d, want)
			}
		}
	}
}

func TestAttempt_PreAttemptExpiry_NeverCallsSender(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	// ts + ttl is well before now.
	_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now.Add(-2*time.Hour), envelope.MinTTL)
	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)
	if err := st.EnqueueOutbound(env.ID, raw, now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rec, _, _ := st.GetOutbox(env.ID)

	sender := &fakeSender{responses: []fakeResponse{{status: 200}}}
	transition, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), rec)
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if transition != TransitionDeadExpired {
		t.Fatalf("expected dead_expired, got %s", transition)
	}
	if sender.calls != 0 {
		t.Fatalf("sender must never be called for an already-expired envelope, got %d calls", sender.calls)
	}
	dead, err := st.ListDead()
	if err != nil {
		t.Fatalf("ListDead: %v", err)
	}
	if len(dead) != 1 || dead[0].State != store.StateDeadExpired {
		t.Fatalf("expected 1 dead_expired record, got %+v", dead)
	}
}

func TestAttempt_TransitionTable(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	tests := []struct {
		name           string
		response       fakeResponse
		wantTransition Transition
		wantFinal      store.OutboxState // zero value means "record removed"
	}{
		{"2xx delivered", fakeResponse{status: 200}, TransitionDelivered, ""},
		{"network failure retries", fakeResponse{err: errors.New("connection refused")}, TransitionRetry, store.StateQueued},
		{"5xx retries", fakeResponse{status: 503}, TransitionRetry, store.StateQueued},
		{"429 without Retry-After treated as 5xx", fakeResponse{status: 429}, TransitionRetry, store.StateQueued},
		{"non-429 4xx dead-letters", fakeResponse{status: 403}, TransitionDeadRejected, store.StateDeadRejected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := openTestStore(t)
			_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, 3600)
			var env envelope.Envelope
			_ = json.Unmarshal(raw, &env)
			if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
				t.Fatalf("enqueue: %v", err)
			}
			rec, _, _ := st.GetOutbox(env.ID)

			sender := &fakeSender{responses: []fakeResponse{tt.response}}
			transition, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), rec)
			if err != nil {
				t.Fatalf("Attempt: %v", err)
			}
			if transition != tt.wantTransition {
				t.Fatalf("transition = %s, want %s", transition, tt.wantTransition)
			}

			got, found, err := st.GetOutbox(env.ID)
			if err != nil {
				t.Fatalf("GetOutbox: %v", err)
			}
			if tt.wantFinal == "" {
				if found {
					t.Fatalf("expected record removed, got %+v", got)
				}
				return
			}
			if !found || got.State != tt.wantFinal {
				t.Fatalf("expected state %s, got found=%v state=%v", tt.wantFinal, found, got.State)
			}
		})
	}
}

func TestAttempt_RetryAfterHonoredWithinTTL(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, 3600) // remaining TTL: 1h
	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)
	if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rec, _, _ := st.GetOutbox(env.ID)

	sender := &fakeSender{responses: []fakeResponse{{status: 429, retryAfter: 5 * time.Second, hasRetryAfter: true}}}
	transition, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), rec)
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if transition != TransitionRetryAfterHonored {
		t.Fatalf("expected retry_after_honored, got %s", transition)
	}
	got, _, _ := st.GetOutbox(env.ID)
	wantNextAt := now.Add(5 * time.Second)
	if !got.NextAt.Equal(wantNextAt) {
		t.Fatalf("expected next_at=%v (Retry-After honored exactly), got %v", wantNextAt, got.NextAt)
	}
}

func TestAttempt_RetryAfterExceedingTTL_TreatedAs5xx(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	ttl := 60 // remaining TTL: 60s
	_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, ttl)
	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)
	if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rec, _, _ := st.GetOutbox(env.ID)

	// Retry-After (1000s) far exceeds the remaining TTL (60s) — must NOT be
	// honored; falls back to full-jitter backoff instead.
	sender := &fakeSender{responses: []fakeResponse{{status: 429, retryAfter: 1000 * time.Second, hasRetryAfter: true}}}
	cfg := DefaultConfig()
	transition, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, cfg, rec)
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if transition != TransitionRetry {
		t.Fatalf("expected plain retry (not retry_after_honored), got %s", transition)
	}
	got, _, _ := st.GetOutbox(env.ID)
	delay := got.NextAt.Sub(now)
	if delay > cfg.BackoffCap {
		t.Fatalf("expected delay bounded by backoff cap %v, got %v (looks like the oversized Retry-After leaked through)", cfg.BackoffCap, delay)
	}
}

// awpd-outbox §2 rule 4: same bytes every attempt.
func TestAttempt_SameBytesEveryAttempt(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	_, raw := signedEnvelope(t, priv, "k1", "example.com#tool", now, 3600)
	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)
	if err := st.EnqueueOutbound(env.ID, raw, now); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	sender := &fakeSender{responses: []fakeResponse{
		{err: errors.New("down")},
		{status: 200},
	}}
	cfg := DefaultConfig()

	rec, _, _ := st.GetOutbox(env.ID)
	if _, err := Attempt(context.Background(), st, clock.NewFixed(now), sender, cfg, rec); err != nil {
		t.Fatalf("attempt 1: %v", err)
	}
	rec2, found, _ := st.GetOutbox(env.ID)
	if !found {
		t.Fatal("expected record still queued after first failed attempt")
	}
	if _, err := Attempt(context.Background(), st, clock.NewFixed(now.Add(time.Minute)), sender, cfg, rec2); err != nil {
		t.Fatalf("attempt 2: %v", err)
	}

	if len(sender.sentRaw) != 2 {
		t.Fatalf("expected 2 send calls, got %d", len(sender.sentRaw))
	}
	if string(sender.sentRaw[0]) != string(raw) || string(sender.sentRaw[1]) != string(raw) {
		t.Fatalf("bytes sent were not byte-identical across attempts")
	}
}

func TestProcessDue_OneInFlightPerDomain(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	// Two records for the SAME destination domain, both due now.
	_, raw1 := signedEnvelope(t, priv, "k1", "example.com#tool-a", now, 3600)
	_, raw2 := signedEnvelope(t, priv, "k1", "example.com#tool-b", now, 3600)
	var env1, env2 envelope.Envelope
	_ = json.Unmarshal(raw1, &env1)
	_ = json.Unmarshal(raw2, &env2)
	if err := st.EnqueueOutbound(env1.ID, raw1, now); err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	if err := st.EnqueueOutbound(env2.ID, raw2, now); err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}

	sender := &fakeSender{responses: []fakeResponse{{status: 200}}}
	processed, err := ProcessDue(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), 10)
	if err != nil {
		t.Fatalf("ProcessDue: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected exactly 1 processed (one in-flight per domain), got %d", processed)
	}
	if sender.calls != 1 {
		t.Fatalf("expected exactly 1 send call, got %d", sender.calls)
	}

	// Exactly one of the two records should have been delivered (removed);
	// the other remains queued for the next tick.
	_, found1, _ := st.GetOutbox(env1.ID)
	_, found2, _ := st.GetOutbox(env2.ID)
	remaining := 0
	if found1 {
		remaining++
	}
	if found2 {
		remaining++
	}
	if remaining != 1 {
		t.Fatalf("expected exactly 1 record still queued after one tick, got %d", remaining)
	}
}

func TestProcessDue_DifferentDomainsProcessConcurrently(t *testing.T) {
	st := openTestStore(t)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)

	_, rawA := signedEnvelope(t, priv, "k1", "a.example.com#tool", now, 3600)
	_, rawB := signedEnvelope(t, priv, "k1", "b.example.com#tool", now, 3600)
	var envA, envB envelope.Envelope
	_ = json.Unmarshal(rawA, &envA)
	_ = json.Unmarshal(rawB, &envB)
	if err := st.EnqueueOutbound(envA.ID, rawA, now); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	if err := st.EnqueueOutbound(envB.ID, rawB, now); err != nil {
		t.Fatalf("enqueue B: %v", err)
	}

	sender := &fakeSender{responses: []fakeResponse{{status: 200}}}
	processed, err := ProcessDue(context.Background(), st, clock.NewFixed(now), sender, DefaultConfig(), 10)
	if err != nil {
		t.Fatalf("ProcessDue: %v", err)
	}
	if processed != 2 {
		t.Fatalf("expected both distinct-domain records processed in one tick, got %d", processed)
	}
}
