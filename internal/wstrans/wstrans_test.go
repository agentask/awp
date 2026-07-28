package wstrans

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func openTestGate(t *testing.T, resolver inbox.KeyResolver, clk clock.Clock) *inbox.Gate {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "wstrans.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &inbox.Gate{Store: st, Keys: resolver, Clock: clk}
}

// testServer starts a real TLS+HTTP server whose mux mounts a
// wstrans.Server at /awp/ws, and returns the endpoint URL and a client
// TLS config trusting exactly this server's certificate (a stand-in
// trust anchor, not real WebPKI — httptest's own self-signed cert).
type testServer struct {
	httpSrv *httptest.Server
	pool    *x509.CertPool
}

func startTestServer(t *testing.T, gate *inbox.Gate) *testServer {
	t.Helper()
	wsSrv := &Server{Gate: gate}
	mux := http.NewServeMux()
	mux.HandleFunc("/awp/ws", wsSrv.ServeHTTP)
	httpSrv := httptest.NewTLSServer(mux)
	t.Cleanup(httpSrv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(httpSrv.Certificate())
	return &testServer{httpSrv: httpSrv, pool: pool}
}

// endpoint returns this test server's wss:// URL — the same
// https-to-wss scheme swap awp-ws-v0.1.md §2 documents.
func (ts *testServer) endpoint() string {
	return "wss" + strings.TrimPrefix(ts.httpSrv.URL, "https") + "/awp/ws"
}

func newTestSender(pool *x509.CertPool, resolve EndpointResolver) *Sender {
	return &Sender{
		TLSConfig:       &tls.Config{RootCAs: pool},
		ResolveEndpoint: resolve,
		DialTimeout:     3 * time.Second,
	}
}

func TestFrameRoundTrip_Unmasked(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"hello":"world"}`)
	if err := writeFrame(&buf, opcodeBinary, payload, false); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	opcode, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if opcode != opcodeBinary {
		t.Fatalf("opcode = %#x, want %#x", opcode, opcodeBinary)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %s, want %s", got, payload)
	}
}

func TestFrameRoundTrip_Masked(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"hello":"world","longer":"payload to exercise multi-byte masking across the 4-byte key cycle"}`)
	if err := writeFrame(&buf, opcodeText, payload, true); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	// A masked frame's payload bytes on the wire must differ from the
	// plaintext (masking actually happened), while still round-tripping.
	if bytes.Contains(buf.Bytes(), payload) {
		t.Fatal("masked frame's wire bytes contain the plaintext payload verbatim — masking did not happen")
	}
	opcode, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if opcode != opcodeText {
		t.Fatalf("opcode = %#x, want %#x", opcode, opcodeText)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %s, want %s", got, payload)
	}
}

func TestFrameRoundTrip_ExtendedLength16(t *testing.T) {
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte("x"), 200) // > 125, forces the 16-bit extended-length form
	if err := writeFrame(&buf, opcodeBinary, payload, false); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	_, got, err := readFrame(&buf)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("got %d bytes, want %d", len(got), len(payload))
	}
}

func TestReadFrame_RejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	// Hand-craft a 64-bit extended-length prefix bigger than MaxFrameSize
	// without actually allocating+writing that much payload data —
	// readFrame must bail before attempting to read it.
	buf.Write([]byte{0x82, 127}) // FIN=1, opcode=binary, unmasked, len=127 (use 64-bit form)
	var lenBuf [8]byte
	oversized := uint64(MaxFrameSize + 1)
	for i := 7; i >= 0; i-- {
		lenBuf[i] = byte(oversized)
		oversized >>= 8
	}
	buf.Write(lenBuf[:])

	_, _, err := readFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_RejectsFragmented(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0x00}) // FIN=0, opcode=binary, unmasked, len=0
	_, _, err := readFrame(&buf)
	if !errors.Is(err, ErrFragmentedFrame) {
		t.Fatalf("expected ErrFragmentedFrame, got %v", err)
	}
}

func TestHandshake_ClientServerRoundTrip(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, gate)

	conn, err := Dial(ts.endpoint(), &tls.Config{RootCAs: ts.pool}, 3*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
}

func TestDial_RejectsPlainWS(t *testing.T) {
	_, err := Dial("ws://example.com/awp/ws", &tls.Config{}, time.Second)
	if err == nil {
		t.Fatal("expected Dial to reject a plain ws:// endpoint")
	}
}

// awp-ws-v0.1.md §5 rule 1: gate equivalence — a valid envelope
// delivered over awp-ws/1 gets exactly the outcome the HTTPS gate would
// give it (here: 202, durably enqueued).
func TestSend_GateEquivalence_ValidEnvelopeAccepted(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{"a.example.com/k1": pub}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, gate)

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
	ts := startTestServer(t, gate)

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
	ts := startTestServer(t, gate)

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

// awp-ws-v0.1.md §4/§7: many envelopes multiplexed concurrently on ONE
// connection, correlated by id — the property that distinguishes this
// transport's client from internal/quictrans's (one stream per envelope
// there, needing no id-based correlation at all).
func TestSend_ManyConcurrentEnvelopesOneConnection(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	resolver := &fakeResolver{keys: map[string]ed25519.PublicKey{"a.example.com/k1": pub}}
	gate := openTestGate(t, resolver, clock.NewFixed(now))
	ts := startTestServer(t, gate)

	sender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		return ts.endpoint(), true, nil
	})
	defer sender.Close()

	const n = 100
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			raw := signedEnvelope(t, priv, "k1", "a.example.com", "b.example.com#tool", now, 3600)
			status, _, _, err := sender.Send(context.Background(), "b.example.com", raw)
			if err != nil {
				errs <- fmt.Errorf("Send: %w", err)
				return
			}
			if status != 202 {
				errs <- fmt.Errorf("status = %d, want 202", status)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	sender.mu.Lock()
	numConns := len(sender.conns)
	sender.mu.Unlock()
	if numConns != 1 {
		t.Fatalf("expected all %d concurrent sends to share exactly 1 connection, got %d", n, numConns)
	}
}

// awp-ws-v0.1.md §5 rule 2: fall back to the next transport on
// awp-ws/1 connection failure or absent advertisement — same bytes, same
// domain.
func TestFallbackSender_FallsBackWhenNoTransportAdvertised(t *testing.T) {
	wsSender := newTestSender(x509.NewCertPool(), func(domain string) (string, bool, error) {
		return "", false, nil // no awp-ws/1 transport advertised
	})
	defer wsSender.Close()

	var fallbackCalledWith []byte
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalledWith = raw
		return 202, 0, false, nil
	})

	fs := &FallbackSender{Primary: wsSender, Fallback: fallback}
	raw := []byte(`{"id":"whatever"}`)
	status, _, _, err := fs.Send(context.Background(), "no-ws.example.com", raw)
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
	wsSender := newTestSender(x509.NewCertPool(), func(domain string) (string, bool, error) {
		return "wss://127.0.0.1:1/awp/ws", true, nil // nothing listens here
	})
	wsSender.DialTimeout = 500 * time.Millisecond
	defer wsSender.Close()

	fallbackCalled := false
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalled = true
		return 202, 0, false, nil
	})

	fs := &FallbackSender{Primary: wsSender, Fallback: fallback}
	status, _, _, err := fs.Send(context.Background(), "down.example.com", []byte(`{}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback to be called after a dial failure")
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
	ts := startTestServer(t, gate)

	wsSender := newTestSender(ts.pool, func(domain string) (string, bool, error) {
		return ts.endpoint(), true, nil
	})
	defer wsSender.Close()

	fallbackCalled := false
	fallback := fallbackFunc(func(ctx context.Context, domain string, raw []byte) (int, time.Duration, bool, error) {
		fallbackCalled = true
		return 0, 0, false, errors.New("should not be called")
	})

	fs := &FallbackSender{Primary: wsSender, Fallback: fallback}
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
