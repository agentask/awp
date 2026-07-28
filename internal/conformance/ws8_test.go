package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/store"
)

// newTargetDaemonWS builds a real local instance with awp-ws/1 enabled to
// run conformance checks against. Unlike newTargetDaemon, its listener
// MUST be real TLS (httptest.NewTLSServer) — awp-ws/1 shares that exact
// listener (awp-ws-v0.1.md §0/§1), so there is no plain-HTTP variant to
// reuse newTargetDaemon's non-TLS httptest.Server for.
func newTargetDaemonWS(t *testing.T, domain, kid string) (ed25519.PrivateKey, *domainTable, *http.Client, *tls.Config) {
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

	table := newDomainTable()
	pool := x509.NewCertPool()
	tlsClientConfig := &tls.Config{RootCAs: pool} //nolint:gosec // test-local self-signed cert added below, no real WebPKI available
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsClientConfig}, Timeout: 5 * time.Second}

	resolver := &keyresolver.HTTPResolver{
		Store: st, Clock: clock.Real{}, Client: httpClient,
		BaseURL: func(d string) string { return table.get(d) },
	}

	d, err := daemon.New(daemon.Config{
		Domain: domain, Kid: kid, Priv: priv, Store: st, Clock: clock.Real{}, Resolver: resolver,
		HTTP: httpClient,
		WS:   &daemon.WSConfig{ClientTLSConfig: tlsClientConfig, ClientDialTimeout: 2 * time.Second},
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

	return priv, table, httpClient, tlsClientConfig
}

// TestRun_WithWSAndCallerKey mirrors TestRun_WithQUICAndCallerKey for
// this binding: CallerDomain/CallerKid/CallerPriv are the target's OWN
// signing identity (self-signed probe, exactly as sync_sig_test.go's
// pattern) — checkWSCrossTransportDedupe's envelope must actually verify
// against the target's own index for its 202/200 sequence to mean
// anything.
func TestRun_WithWSAndCallerKey(t *testing.T) {
	const domain = "target-ws.example.com"
	priv, table, httpClient, tlsClientConfig := newTargetDaemonWS(t, domain, "k1")

	report := Run(context.Background(), domain, Options{
		BaseURL:       baseURLOpt(table),
		HTTP:          httpClient,
		CallerDomain:  domain,
		CallerKid:     "k1",
		CallerPriv:    priv,
		QUICTLSConfig: tlsClientConfig,
	})

	byID := map[string]CheckResult{}
	for _, r := range report.Results {
		byID[r.ID] = r
	}

	mustPass := []string{"ws-7.1", "ws-7.2", "ws-7.3", "ws-7.4", "ws-7.5"}
	for _, id := range mustPass {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing check %s", id)
		}
		if r.Status != Pass {
			t.Fatalf("check %s: status=%s detail=%s (want Pass)", id, r.Status, r.Detail)
		}
	}
	if !report.OK() {
		t.Fatalf("report has failures: %+v", report.Results)
	}
}
