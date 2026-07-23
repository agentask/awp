package quictrans

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/inbox"
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

type fakeResolver struct{ keys map[string]ed25519.PublicKey }

func (f *fakeResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := f.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}
func (f *fakeResolver) Refresh(string) error { return nil }

func signedEnvelope(t *testing.T, priv ed25519.PrivateKey, kid, from, to string, now time.Time, ttl int) []byte {
	t.Helper()
	e := &envelope.Envelope{
		Awp: "0.1", ID: envelope.NewID(), Kind: "message",
		From: from, To: to, Thread: envelope.NewID(),
		Ts: now.Format(time.RFC3339), TTL: ttl,
		Body: json.RawMessage(`{"type":"text","text":"hi"}`),
	}
	if err := e.Sign(priv, kid); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// testServer starts a real QUIC listener wrapping the given Gate, and
// returns the Sender-facing pieces needed to dial it: the endpoint and a
// client TLS config that trusts exactly this server's certificate (a
// stand-in trust anchor, not real WebPKI — see testcert_test.go).
type testServer struct {
	ln     *quic.Listener
	server *Server
	pool   *x509.CertPool
}

func startTestServer(t *testing.T, domain string, gate *inbox.Gate) *testServer {
	t.Helper()
	cert, x509Cert := generateTestCert(t, domain)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"awp/1"},
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatalf("ListenAddr: %v", err)
	}
	srv := &Server{Gate: gate}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})

	pool := x509.NewCertPool()
	pool.AddCert(x509Cert)
	return &testServer{ln: ln, server: srv, pool: pool}
}

func (ts *testServer) endpoint() string { return ts.ln.Addr().String() }

func newTestSender(pool *x509.CertPool, resolve EndpointResolver) *Sender {
	return &Sender{
		TLSConfig:       &tls.Config{RootCAs: pool, NextProtos: []string{"awp/1"}},
		ResolveEndpoint: resolve,
		DialTimeout:     3 * time.Second,
	}
}

func openTestGate(t *testing.T, resolver inbox.KeyResolver, clk clock.Clock) *inbox.Gate {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "quictrans.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &inbox.Gate{Store: st, Keys: resolver, Clock: clk}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"hello":"world"}`)
	if err := writeFrame(&buf, payload); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %s, want %s", got, payload)
	}
}

func TestReadFrame_RejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	oversized := make([]byte, MaxFrameSize+1)
	// Hand-craft a length prefix bigger than MaxFrameSize without actually
	// allocating+writing that much payload data (readFrame must bail before
	// attempting to read it).
	lenPrefix := []byte{0, 0, 0, 0}
	lenPrefix[0] = byte(len(oversized) >> 24)
	lenPrefix[1] = byte(len(oversized) >> 16)
	lenPrefix[2] = byte(len(oversized) >> 8)
	lenPrefix[3] = byte(len(oversized))
	buf.Write(lenPrefix)

	_, err := readFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

// awp-quic §5 rule 1: gate equivalence — a valid envelope delivered over
// awp/1 gets exactly the outcome the HTTPS gate would give it (here: 202,
// durably enqueued).
func TestSend_GateEquivalence_ValidEnvelopeAccepted(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{"a.example.com/k1": pub}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, "b.example.com", gate)

	sender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		return ts.endpoint(), true, nil
	})
	defer sender.Close()

	raw := signedEnvelope(t, priv, "k1", "a.example.com", "b.example.com#tool", now, 3600)

	var env envelope.Envelope
	_ = json.Unmarshal(raw, &env)

	status, _, _, err := sender.Send(context.Background(), "b.example.com", raw)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if status != 202 {
		t.Fatalf("status = %d, want 202", status)
	}

	queued, err := gate.Store.HasQueued(env.ID)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if !queued {
		t.Fatal("expected the envelope durably enqueued via the same Gate, exactly as HTTPS would")
	}
}

func TestSend_GateEquivalence_BadSignatureRejected(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{}} // no key registered
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, "b.example.com", gate)

	sender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		return ts.endpoint(), true, nil
	})
	defer sender.Close()

	raw := signedEnvelope(t, priv, "k1", "a.example.com", "b.example.com#tool", now, 3600)
	status, _, _, err := sender.Send(context.Background(), "b.example.com", raw)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if status != 401 {
		t.Fatalf("status = %d, want 401 (unresolvable key)", status)
	}
}

func TestSend_ReusesConnectionAcrossSends(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{"a.example.com/k1": pub}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, "b.example.com", gate)

	calls := 0
	sender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		calls++
		return ts.endpoint(), true, nil
	})
	defer sender.Close()

	for range 3 {
		raw := signedEnvelope(t, priv, "k1", "a.example.com", "b.example.com#tool", now, 3600)
		if _, _, _, err := sender.Send(context.Background(), "b.example.com", raw); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if calls != 3 {
		t.Fatalf("expected 3 resolve calls, got %d", calls)
	}
	sender.mu.Lock()
	numConns := len(sender.conns)
	sender.mu.Unlock()
	if numConns != 1 {
		t.Fatalf("expected exactly 1 cached connection reused across sends, got %d", numConns)
	}
}

// awp-quic §5 rule 2: fall back to HTTPS on QUIC connection failure,
// timeout, or absent advertisement — same bytes, same domain.
func TestFallbackSender_FallsBackWhenNoTransportAdvertised(t *testing.T) {
	quicSender := newTestSender(x509.NewCertPool(), func(domain string) (string, bool, error) {
		return "", false, nil // no awp/1 transport advertised
	})
	defer quicSender.Close()

	var fallbackCalledWith []byte
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalledWith = raw
		return 202, 0, false, nil
	})

	fs := &FallbackSender{Primary: quicSender, Fallback: fallback}
	raw := []byte(`{"id":"whatever"}`)
	status, _, _, err := fs.Send(context.Background(), "no-quic.example.com", raw)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if status != 202 {
		t.Fatalf("status = %d, want 202 (from fallback)", status)
	}
	if string(fallbackCalledWith) != string(raw) {
		t.Fatal("fallback was not called with the exact same bytes")
	}
}

func TestFallbackSender_FallsBackOnDialFailure(t *testing.T) {
	quicSender := newTestSender(x509.NewCertPool(), func(domain string) (string, bool, error) {
		return "127.0.0.1:1", true, nil // nothing listens here
	})
	quicSender.DialTimeout = 500 * time.Millisecond
	defer quicSender.Close()

	fallbackCalled := false
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalled = true
		return 202, 0, false, nil
	})

	fs := &FallbackSender{Primary: quicSender, Fallback: fallback}
	status, _, _, err := fs.Send(context.Background(), "down.example.com", []byte(`{}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback to be called after a QUIC dial failure")
	}
	if status != 202 {
		t.Fatalf("status = %d, want 202 (from fallback)", status)
	}
}

func TestFallbackSender_NoFallbackWhenPrimarySucceeds(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{"a.example.com/k1": pub}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, "b.example.com", gate)

	quicSender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		return ts.endpoint(), true, nil
	})
	defer quicSender.Close()

	fallbackCalled := false
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalled = true
		return 0, 0, false, errors.New("should not be called")
	})

	fs := &FallbackSender{Primary: quicSender, Fallback: fallback}
	raw := signedEnvelope(t, priv, "k1", "a.example.com", "b.example.com#tool", now, 3600)
	status, _, _, err := fs.Send(context.Background(), "b.example.com", raw)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if status != 202 {
		t.Fatalf("status = %d, want 202", status)
	}
	if fallbackCalled {
		t.Fatal("fallback must not be called when the primary transport succeeds")
	}
}

type fallbackFunc func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error)

func (f fallbackFunc) Send(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
	return f(ctx, domain, raw)
}
