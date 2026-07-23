package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/store"
)

// domainTable is the same "DNS stand-in" pattern used in
// internal/daemon's e2e tests: maps a domain to the real local base URL
// its httptest.Server ended up on.
type domainTable struct {
	mu sync.Mutex
	m  map[string]string
}

func newDomainTable() *domainTable { return &domainTable{m: map[string]string{}} }
func (t *domainTable) set(domain, base string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[domain] = base
}
func (t *domainTable) get(domain string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[domain]
}

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

// newTargetDaemon builds a real local instance to run conformance checks
// against, optionally with QUIC enabled. Returns the daemon, its own
// signing key (for self-test-capable checks), and the domain table.
func newTargetDaemon(t *testing.T, domain, kid string, withQUIC bool) (*daemon.Daemon, ed25519.PrivateKey, *domainTable, *http.Client) {
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
	resolver := &keyresolver.HTTPResolver{Store: st, Clock: clock.Real{}, BaseURL: func(d string) string { return table.get(d) }}

	cfg := daemon.Config{Domain: domain, Kid: kid, Priv: priv, Store: st, Clock: clock.Real{}, Resolver: resolver}
	var pool *x509.CertPool
	if withQUIC {
		cert, x509Cert := generateTestCert(t, domain)
		pool = x509.NewCertPool()
		pool.AddCert(x509Cert)
		cfg.QUIC = &daemon.QUICConfig{
			ListenAddr:        "127.0.0.1:0",
			ServerTLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"awp/1"}},
			ClientTLSConfig:   &tls.Config{RootCAs: pool, NextProtos: []string{"awp/1"}},
			ClientDialTimeout: 2 * time.Second,
			ClientQUICConfig:  &quic.Config{HandshakeIdleTimeout: 400 * time.Millisecond},
		}
	}

	d, err := daemon.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if withQUIC {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = d.ServeQUIC(ctx) }()
	}

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	table.set(domain, srv.URL)

	var transports []identity.Transport
	if withQUIC {
		transports = []identity.Transport{{Proto: "awp/1", Endpoint: d.QUICAddr()}}
	}
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", transports); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	return d, priv, table, httpClient
}

func baseURLOpt(table *domainTable) func(string) string {
	return func(domain string) string { return table.get(domain) }
}

func TestRun_WithoutCallerKey_HTTPSOnly(t *testing.T) {
	const domain = "target-no-key.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table),
		HTTP:    httpClient,
	})

	byID := map[string]CheckResult{}
	for _, r := range report.Results {
		byID[r.ID] = r
	}

	mustPass := []string{"core-5.1", "core-5.2-malformed", "core-5.2-ttl-bounds", "core-5.2-expired", "core-5.2-unknown-signer", "quic-8.1"}
	for _, id := range mustPass {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing check %s", id)
		}
		if r.Status != Pass {
			t.Fatalf("check %s: status=%s detail=%s (want Pass)", id, r.Status, r.Detail)
		}
	}

	mustSkip := []string{"core-5.2-accept-and-dedupe", "core-5.3-retention", "core-5.4-delegation", "core-5.5-unknown-body-type", "core-5.7-two-party", "quic-8.2", "quic-8.3", "quic-8.4", "quic-8.5"}
	for _, id := range mustSkip {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing check %s", id)
		}
		if r.Status != Skip {
			t.Fatalf("check %s: status=%s (want Skip)", id, r.Status)
		}
	}

	if !report.OK() {
		t.Fatalf("report has failures: %+v", report.Results)
	}
}

func TestRun_WithCallerKey_HTTPSOnly(t *testing.T) {
	const domain = "target-with-key.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL:      baseURLOpt(table),
		HTTP:         httpClient,
		CallerDomain: domain,
		CallerKid:    "k1",
		CallerPriv:   priv,
	})

	byID := map[string]CheckResult{}
	for _, r := range report.Results {
		byID[r.ID] = r
	}
	if r := byID["core-5.2-accept-and-dedupe"]; r.Status != Pass {
		t.Fatalf("core-5.2-accept-and-dedupe: status=%s detail=%s", r.Status, r.Detail)
	}
	if r := byID["core-5.3-retention"]; r.Status != Skip {
		t.Fatalf("core-5.3-retention should Skip without --thorough, got %s", r.Status)
	}
	if !report.OK() {
		t.Fatalf("report has failures: %+v", report.Results)
	}
}

func TestRun_WithQUICAndCallerKey(t *testing.T) {
	const domain = "target-quic.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", true)

	report := Run(context.Background(), domain, Options{
		BaseURL:       baseURLOpt(table),
		HTTP:          httpClient,
		CallerDomain:  domain,
		CallerKid:     "k1",
		CallerPriv:    priv,
		QUICTLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-local self-signed cert, no real WebPKI available
	})

	byID := map[string]CheckResult{}
	for _, r := range report.Results {
		byID[r.ID] = r
	}

	mustPass := []string{"quic-8.1", "quic-8.2", "quic-8.3", "quic-8.4", "quic-8.5"}
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

// TestRun_RetentionCheckAlwaysSkips confirms core-5.3-retention reports
// Skip unconditionally — see checkRetention's doc comment for why this
// checklist item cannot be a real black-box probe.
func TestRun_RetentionCheckAlwaysSkips(t *testing.T) {
	const domain = "target-retention.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL:      baseURLOpt(table),
		HTTP:         httpClient,
		CallerDomain: domain,
		CallerKid:    "k1",
		CallerPriv:   priv,
	})

	for _, r := range report.Results {
		if r.ID == "core-5.3-retention" {
			if r.Status != Skip {
				t.Fatalf("core-5.3-retention: status=%s detail=%s (want Skip)", r.Status, r.Detail)
			}
			return
		}
	}
	t.Fatal("core-5.3-retention check missing from report")
}

func TestRun_UnreachableDomain(t *testing.T) {
	report := Run(context.Background(), "totally-unreachable.invalid", Options{
		BaseURL: func(domain string) string { return "http://127.0.0.1:1" },
		HTTP:    &http.Client{Timeout: 500 * time.Millisecond},
	})
	if report.OK() {
		t.Fatal("expected a failure for an unreachable domain")
	}
	found := false
	for _, r := range report.Results {
		if r.ID == "core-5.1" && r.Status == Fail {
			found = true
		}
	}
	if !found {
		t.Fatal("expected core-5.1 to fail for an unreachable domain")
	}
}
