package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/store"
	"github.com/agentask/awp/internal/wstrans"
)

// newTestInstanceWS builds a real local instance with awp-ws/1 enabled.
// Unlike newTestInstance/newTestInstanceQUIC, its HTTPS side is a REAL
// TLS server (httptest.NewTLSServer), not the plain-HTTP stand-in used
// elsewhere in this package's e2e tests — awp-ws/1 shares that exact
// listener (awp-ws-v0.1.md §0/§1: no separate bind address), so a
// non-TLS listener would make wss:// impossible to offer at all. pool
// accumulates every WS-enabled instance's TLS certificate so other
// instances constructed against the same pool trust it.
func newTestInstanceWS(t *testing.T, domain, kid string, clk clock.Clock, table *domainTable, pool *x509.CertPool) *Daemon {
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

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resolver := &keyresolver.HTTPResolver{
		Store: st, Clock: clk, Client: httpClient,
		BaseURL: func(d string) string { return table.get(d) },
	}

	d, err := New(Config{
		Domain:   domain,
		Kid:      kid,
		Priv:     priv,
		Store:    st,
		Clock:    clk,
		Resolver: resolver,
		HTTP:     httpClient,
		WS: &WSConfig{
			ClientTLSConfig:   &tls.Config{RootCAs: pool},
			ClientDialTimeout: 2 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	srv := httptest.NewTLSServer(d)
	t.Cleanup(srv.Close)
	table.set(domain, srv.URL)
	pool.AddCert(srv.Certificate())

	transports := []identity.Transport{{Proto: "awp-ws/1", Endpoint: d.WSEndpoint(srv.URL)}}
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", transports); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}
	return d
}

// TestE2E_MessageAckReplyClose_OverWS is the awp-ws counterpart of
// CLAUDE.md's Phase 4.5 gate ("the E2E test passes once per transport"),
// extended to this later-added binding: both instances have working
// awp-ws/1 endpoints; delivery happens over WebSocket throughout
// (FallbackSender only falls back on failure, and nothing fails here).
func TestE2E_MessageAckReplyClose_OverWS(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	a := newTestInstanceWS(t, "a-ws.example.com", "k1", clock.NewFixed(now), table, pool)
	b := newTestInstanceWS(t, "b-ws.example.com", "k1", clock.NewFixed(now), table, pool)

	verifyClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	runMessageAckReplyCloseFlow(t, ctx, a, b, table, verifyClient)
}

// TestE2E_WSFailureFallsBackToHTTPS mirrors
// TestE2E_QUICFailureFallsBackToHTTPS for this binding: A has awp-ws/1
// enabled; B advertises an awp-ws/1 endpoint nothing listens on
// (simulating the receiver's WS service being down while HTTPS stays
// up), so every attempt from A must fall back — yet the full four-
// envelope thread still completes exactly as it would with no WS
// involved at all.
func TestE2E_WSFailureFallsBackToHTTPS(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	a := newTestInstanceWS(t, "a-ws-fallback.example.com", "k1", clock.NewFixed(now), table, pool)
	// B's own resolver/outbound sender must trust A's self-signed TLS
	// cert too — B fetches A's index to verify inbound signatures, and
	// delivers acks/replies back to A's https:// inbox.
	peerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	// B: ordinary HTTPS-only backing, but its index LIES about an
	// awp-ws/1 transport at a dead address.
	b := newTestInstance(t, "b-ws-fallback.example.com", "k1", clock.NewFixed(now), table,
		[]identity.Transport{{Proto: "awp-ws/1", Endpoint: "wss://127.0.0.1:1/awp/ws"}}, peerClient)

	runMessageAckReplyCloseFlow(t, ctx, a, b, table, peerClient)
}

// TestDedupe_AcrossWSAndHTTPS mirrors TestDedupe_AcrossTransports for
// this binding: the exact same signed envelope arrives first over
// awp-ws/1, then over HTTPS — one `seen` store dedupes it regardless of
// which transport adapter handed the receiver the bytes.
func TestDedupe_AcrossWSAndHTTPS(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	table := newDomainTable()
	pool := x509.NewCertPool()

	sender := newTestInstanceWS(t, "ws-sender.example.com", "k1", clock.NewFixed(now), table, pool)
	receiver := newTestInstanceWS(t, "ws-receiver.example.com", "k1", clock.NewFixed(now), table, pool)

	threadID := envelope.NewID()
	env, err := sender.Send("message", receiver.Domain, threadID, nil, json.RawMessage(`{"type":"text","text":"hi"}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	rec, found, err := sender.Store.GetOutbox(env.ID)
	if err != nil || !found {
		t.Fatalf("GetOutbox: %v found=%v", err, found)
	}

	// First arrival: over awp-ws/1, directly (bypassing the outbox — this
	// test is about the receiver's dedupe, not delivery scheduling).
	wsSender := &wstrans.Sender{
		TLSConfig: &tls.Config{RootCAs: pool},
		ResolveEndpoint: func(domain string) (string, bool, error) {
			return receiver.WSEndpoint(table.get(receiver.Domain)), true, nil
		},
	}
	defer wsSender.Close()
	status1, _, _, err := wsSender.Send(context.Background(), receiver.Domain, rec.Envelope)
	if err != nil {
		t.Fatalf("WS send: %v", err)
	}
	if status1 != 202 {
		t.Fatalf("first arrival (WS): status = %d, want 202", status1)
	}

	// Second arrival: the exact same bytes, over HTTPS.
	status2 := postHTTPS(t, pool, table, receiver.Domain, rec.Envelope)
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

// postHTTPS POSTs raw directly to domain's real (httptest, TLS) inbox,
// trusting pool — the TLS counterpart of quic_e2e_test.go's postHTTP,
// needed here because newTestInstanceWS's listener is real TLS, not the
// plain-HTTP stand-in the rest of this package's e2e tests use.
func postHTTPS(t *testing.T, pool *x509.CertPool, table *domainTable, domain string, raw []byte) int {
	t.Helper()
	base := table.get(domain)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := client.Post(base+"/awp/inbox", "application/awp+json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("https post to %s: %v", domain, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
