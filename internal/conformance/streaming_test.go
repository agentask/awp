package conformance

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/store"
)

// newTargetDaemonNoStreaming mirrors newTargetDaemon, but with streaming
// explicitly disabled — newTargetDaemon has no such toggle and this
// package's convention (established by ws8_test.go's own
// newTargetDaemonWS) is a small standalone helper rather than growing
// newTargetDaemon's signature for every future feature-specific need.
func newTargetDaemonNoStreaming(t *testing.T, domain, kid string) (*domainTable, *http.Client) {
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

	d, err := daemon.New(daemon.Config{Domain: domain, Kid: kid, Priv: priv, Store: st, Clock: clock.Real{}, Resolver: resolver, DisableStreaming: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	table.set(domain, srv.URL)

	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}
	httpClient := &http.Client{Timeout: 5 * time.Second}
	return table, httpClient
}

func TestCheckStreamingCapabilityAdvertised_PresentByDefault(t *testing.T) {
	const domain = "streaming-present.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	r := getCheck(t, report, "awp-streaming-1-capability-advertised")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass", r.Status, r.Detail)
	}
	if r.Detail != "advertises \"awp-streaming-v0.1\"" {
		t.Fatalf("detail=%q, expected to confirm advertisement", r.Detail)
	}
}

func TestCheckStreamingCapabilityAdvertised_AbsentWhenDisabled(t *testing.T) {
	const domain = "streaming-absent.example.com"
	table, httpClient := newTargetDaemonNoStreaming(t, domain, "k1")

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	r := getCheck(t, report, "awp-streaming-1-capability-advertised")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass (absence is not itself non-conformant)", r.Status, r.Detail)
	}
	if r.Detail != "does not advertise \"awp-streaming-v0.1\" — absence is not itself non-conformant" {
		t.Fatalf("detail=%q, expected to confirm non-advertisement", r.Detail)
	}
}

func TestCheckStreamingSignatureVerifiedFirst_UnregisteredSignerRejected(t *testing.T) {
	const domain = "streaming-sig.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	r := getCheck(t, report, "awp-streaming-10.1-signature-verified-before-buffering")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass", r.Status, r.Detail)
	}
}

// TestRun_StreamingSkipsDocumentedAndConsistent confirms the checklist
// items that require observing internal/async state are reported Skip
// with a non-empty reason, not silently omitted or fabricated as Pass.
func TestRun_StreamingSkipsDocumentedAndConsistent(t *testing.T) {
	const domain = "streaming-skips.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	mustSkip := []string{
		"awp-streaming-10.2-out-of-order-reassembly",
		"awp-streaming-10.3-no-gap-delivery",
		"awp-streaming-10.4-bound-enforced",
		"awp-streaming-10.5-non-adopting-rejects",
	}
	for _, id := range mustSkip {
		r := getCheck(t, report, id)
		if r.Status != Skip {
			t.Fatalf("check %s: status=%s, want Skip", id, r.Status)
		}
		if r.Detail == "" {
			t.Fatalf("check %s: Skip with no reason given", id)
		}
	}
	if !report.OK() {
		t.Fatalf("report has failures: %+v", report.Results)
	}
}
