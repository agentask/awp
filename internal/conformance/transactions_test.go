package conformance

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/manifest"
)

func registerEchoTool(t *testing.T, d *daemon.Daemon, baseURL, name string, compensatedBy string) {
	t.Helper()
	if err := d.RegisterTool(baseURL, daemon.Tool{
		Manifest: &manifest.Manifest{
			Awp: "0.1", Name: name, Kind: "tool", Version: "1.0.0",
			Description:   "test",
			Distribution:  manifest.Distribution{Hosted: &manifest.Hosted{}},
			State:         "stateless",
			Auth:          manifest.Auth{Sig: "required"},
			Pricing:       json.RawMessage("null"),
			CompensatedBy: compensatedBy,
		},
		Handler: func(_ context.Context, caller string, _ []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
			return json.RawMessage(`{"ok":true}`), nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool(%s): %v", name, err)
	}
}

func TestCheckMalformedTransactionRejected_NoCallerKey_Skips(t *testing.T) {
	const domain = "txn-no-key.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	r := getCheck(t, report, "awp-transactions-5.2-malformed-header-rejected")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckMalformedTransactionRejected_NoToolEntity_Skips(t *testing.T) {
	const domain = "txn-no-tool.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.2-malformed-header-rejected")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckMalformedTransactionRejected_RealDaemon_Passes(t *testing.T) {
	const domain = "txn-real-daemon.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	registerEchoTool(t, d, table.get(domain), domain+"#echo", "")

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.2-malformed-header-rejected")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass (internal/daemon rejects malformed AWP-Transaction with 400)", r.Status, r.Detail)
	}
}

func TestCheckCompensatedByResolvable_NoneDeclared_Skips(t *testing.T) {
	const domain = "txn-compensate-none.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)
	registerEchoTool(t, d, table.get(domain), domain+"#echo", "")

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.3-compensated-by-resolvable")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckCompensatedByResolvable_SameDomainResolves_Passes(t *testing.T) {
	const domain = "txn-compensate-same-domain.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)
	baseURL := table.get(domain)
	registerEchoTool(t, d, baseURL, domain+"#reserve", domain+"#cancel-reservation")
	registerEchoTool(t, d, baseURL, domain+"#cancel-reservation", "")

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.3-compensated-by-resolvable")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass", r.Status, r.Detail)
	}
}

func TestCheckCompensatedByResolvable_DeclaredButMissing_Fails(t *testing.T) {
	const domain = "txn-compensate-missing.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)
	baseURL := table.get(domain)
	registerEchoTool(t, d, baseURL, domain+"#reserve", domain+"#nonexistent-undo")

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.3-compensated-by-resolvable")
	if r.Status != Fail {
		t.Fatalf("status=%s detail=%s, want Fail (declared compensated_by is not in this domain's own index)", r.Status, r.Detail)
	}
}

func TestCheckCompensatedByResolvable_CrossDomain_Skips(t *testing.T) {
	const domain = "txn-compensate-cross-domain.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)
	baseURL := table.get(domain)
	registerEchoTool(t, d, baseURL, domain+"#reserve", "other-domain.example.com#cancel-reservation")

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-transactions-5.3-compensated-by-resolvable")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip (this checklist item does not follow cross-domain targets)", r.Status, r.Detail)
	}
}
