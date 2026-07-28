package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/quictrans"
	"github.com/agentask/awp/internal/store"
)

// generateTestCert creates a self-signed ed25519 certificate for domain.
// No real WebPKI in a unit test — see internal/quictrans's identical
// helper for the same rationale.
func generateTestCert(t *testing.T, domain string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, cert
}

// newTestInstanceQUIC builds a real local instance with BOTH transports
// live: HTTPS (httptest.Server) and awp/1 (a real QUIC listener). Its
// certificate is added to pool so other instances constructed against the
// same pool will trust it when dialing.
func newTestInstanceQUIC(t *testing.T, domain, kid string, clk clock.Clock, table *domainTable, pool *x509.CertPool) *Daemon {
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

	cert, x509Cert := generateTestCert(t, domain)

	d, err := New(Config{
		Domain:   domain,
		Kid:      kid,
		Priv:     priv,
		Store:    st,
		Clock:    clk,
		Resolver: resolver,
		QUIC: &QUICConfig{
			ListenAddr:        "127.0.0.1:0",
			ServerTLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"awp/1"}},
			ClientTLSConfig:   &tls.Config{RootCAs: pool, NextProtos: []string{"awp/1"}},
			ClientDialTimeout: 2 * time.Second,
			ClientQUICConfig:  &quic.Config{HandshakeIdleTimeout: 400 * time.Millisecond},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.ServeQUIC(ctx) }()

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	table.set(domain, srv.URL)

	pool.AddCert(x509Cert)

	transports := []identity.Transport{{Proto: "awp/1", Endpoint: d.QUICAddr()}}
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", transports); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}
	return d
}

// runMessageAckReplyCloseFlow drives the exact same protocol sequence as
// TestE2E_MessageAckReplyClose and asserts the exact same success criteria
// — factored out so the QUIC, WS, and fallback variants aren't copies
// that could silently drift from what the release criterion actually
// checks. verifyClient is passed to newVerifyResolver for the trailing
// independent re-verification step — nil for plain-HTTP instances, or a
// client trusting a TLS-secured instance's self-signed cert (see
// ws_e2e_test.go).
func runMessageAckReplyCloseFlow(t *testing.T, ctx context.Context, a, b *Daemon, table *domainTable, verifyClient *http.Client) {
	t.Helper()
	threadID := envelope.NewID()
	msg, err := a.Send("message", b.Domain, threadID, nil, json.RawMessage(`{"type":"text","text":"hello B"}`))
	if err != nil {
		t.Fatalf("A send message: %v", err)
	}

	drainOutbox(t, ctx, a)
	drainInbound(t, ctx, b)
	drainOutbox(t, ctx, b)
	drainInbound(t, ctx, a)

	closeEnv, err := a.Send("close", b.Domain, threadID, nil, json.RawMessage(`{"type":"text","text":"bye"}`))
	if err != nil {
		t.Fatalf("A send close: %v", err)
	}
	drainOutbox(t, ctx, a)
	drainInbound(t, ctx, b)

	threadA, found, err := a.Store.GetThread(threadID)
	if err != nil || !found {
		t.Fatalf("A GetThread: %v found=%v", err, found)
	}
	if !threadA.Closed || threadA.ClosedBy != a.Domain {
		t.Fatalf("A's thread not correctly closed: %+v", threadA)
	}
	threadB, found, err := b.Store.GetThread(threadID)
	if err != nil || !found {
		t.Fatalf("B GetThread: %v found=%v", err, found)
	}
	if !threadB.Closed || threadB.ClosedBy != a.Domain {
		t.Fatalf("B's thread not correctly closed: %+v", threadB)
	}

	msgsA, err := a.Store.ThreadMessages(threadID)
	if err != nil {
		t.Fatalf("A ThreadMessages: %v", err)
	}
	msgsB, err := b.Store.ThreadMessages(threadID)
	if err != nil {
		t.Fatalf("B ThreadMessages: %v", err)
	}
	if len(msgsA) != 4 || len(msgsB) != 4 {
		t.Fatalf("expected 4 archived envelopes on each side (exactly-once processing), got A=%d B=%d", len(msgsA), len(msgsB))
	}
	if msgsA[0].ID != msg.ID || msgsA[3].ID != closeEnv.ID {
		t.Fatalf("A's archived envelope order is wrong: %+v", msgsA)
	}

	if deadA, err := a.Store.ListDead(); err != nil || len(deadA) != 0 {
		t.Fatalf("expected no dead letters on A, got %v (err=%v)", deadA, err)
	}
	if deadB, err := b.Store.ListDead(); err != nil || len(deadB) != 0 {
		t.Fatalf("expected no dead letters on B, got %v (err=%v)", deadB, err)
	}

	verifyResolver := newVerifyResolver(t, table, verifyClient)
	for _, m := range msgsA {
		verifyEnvelopeSignature(t, verifyResolver, m.Envelope)
	}
	for _, m := range msgsB {
		verifyEnvelopeSignature(t, verifyResolver, m.Envelope)
	}
}

// TestE2E_MessageAckReplyClose_OverQUIC is CLAUDE.md's Phase 4.5 gate,
// QUIC half: "Phase 4 E2E passes twice — once per transport." Both
// instances have working awp/1 listeners; delivery happens over QUIC
// throughout (FallbackSender only falls back on failure, and nothing fails
// here).
func TestE2E_MessageAckReplyClose_OverQUIC(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	a := newTestInstanceQUIC(t, "a-quic.example.com", "k1", clock.NewFixed(now), table, pool)
	b := newTestInstanceQUIC(t, "b-quic.example.com", "k1", clock.NewFixed(now), table, pool)

	runMessageAckReplyCloseFlow(t, ctx, a, b, table, nil)
}

// TestE2E_QUICFailureFallsBackToHTTPS is the other half of the Phase 4.5
// gate: "WHEN a QUIC attempt fails, the outbox SHALL deliver the same
// bytes over HTTPS and the receiver SHALL process exactly once." A has
// QUIC enabled; B advertises an awp/1 endpoint that nothing listens on
// (simulating the receiver's QUIC service being down while HTTPS stays
// up), so every attempt from A must fall back — yet the full four-envelope
// thread still completes exactly as it would with no QUIC involved at all.
func TestE2E_QUICFailureFallsBackToHTTPS(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	a := newTestInstanceQUIC(t, "a-fallback.example.com", "k1", clock.NewFixed(now), table, pool)
	// B: ordinary HTTPS-only backing, but its index LIES about an awp/1
	// transport at a dead address.
	b := newTestInstance(t, "b-fallback.example.com", "k1", clock.NewFixed(now), table,
		[]identity.Transport{{Proto: "awp/1", Endpoint: "127.0.0.1:1"}}, nil)

	runMessageAckReplyCloseFlow(t, ctx, a, b, table, nil)
}

// TestDedupe_AcrossTransports is the Phase 4.5 gate's dedupe bullet: "WHEN
// the same envelope arrives over both transports, one `seen` store SHALL
// dedupe it." This delivers the exact same signed envelope to the same
// receiver first over awp/1, then over HTTPS, and checks the gate's own
// response codes: 202 (durably enqueued) then 200 (already accepted, per
// core §2.2 gate 4 — not reprocessed).
func TestDedupe_AcrossTransports(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	sender := newTestInstanceQUIC(t, "sender.example.com", "k1", clock.NewFixed(now), table, pool)
	receiver := newTestInstanceQUIC(t, "receiver.example.com", "k1", clock.NewFixed(now), table, pool)

	threadID := envelope.NewID()
	env, err := sender.Send("message", receiver.Domain, threadID, nil, json.RawMessage(`{"type":"text","text":"hi"}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	rec, found, err := sender.Store.GetOutbox(env.ID)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v found=%v", err, found)
	}

	// First arrival: over awp/1, directly (bypassing the outbox — this
	// test is about the receiver's dedupe, not delivery scheduling).
	quicSender := &quictrans.Sender{
		TLSConfig: &tls.Config{RootCAs: pool, NextProtos: []string{"awp/1"}},
		ResolveEndpoint: func(domain string) (string, bool, error) {
			return receiver.QUICAddr(), true, nil
		},
	}
	defer quicSender.Close()
	status1, _, _, err := quicSender.Send(context.Background(), receiver.Domain, rec.Envelope)
	if err != nil {
		t.Fatalf("QUIC send: %v", err)
	}
	if status1 != 202 {
		t.Fatalf("first arrival (QUIC): status = %d, want 202", status1)
	}

	// Second arrival: the exact same bytes, over HTTPS.
	status2 := postHTTP(t, table, receiver.Domain, rec.Envelope)
	if status2 != 200 {
		t.Fatalf("second arrival (HTTPS): status = %d, want 200 (deduped, not reprocessed)", status2)
	}

	queued, err := receiver.Store.HasQueued(env.ID)
	if err != nil {
		t.Fatalf("HasQueued: %v", err)
	}
	if !queued {
		t.Fatal("expected the envelope queued exactly once after arriving over both transports")
	}
}

// postHTTP POSTs raw directly to domain's real (httptest) inbox, resolved
// via table exactly as internal/outbox.HTTPSender would via a fetched
// index — bypassing the sender daemon's own outbox entirely, since this
// helper exists only to prove the RECEIVER dedupes identically regardless
// of which transport adapter handed it the bytes.
func postHTTP(t *testing.T, table *domainTable, domain string, raw []byte) int {
	t.Helper()
	base := table.get(domain)
	resp, err := http.Post(base+"/awp/inbox", "application/awp+json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("http post to %s: %v", domain, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
