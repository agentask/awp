package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/manifest"
)

func getCheck(t *testing.T, report Report, id string) CheckResult {
	t.Helper()
	for _, r := range report.Results {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("missing check %s", id)
	return CheckResult{}
}

func TestCheckResponseSigning_NoCallerKey_Skips(t *testing.T) {
	const domain = "sync-sig-no-key.example.com"
	_, _, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{BaseURL: baseURLOpt(table), HTTP: httpClient})
	r := getCheck(t, report, "awp-sig-3-response-signing")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckResponseSigning_NoToolEntity_Skips(t *testing.T) {
	const domain = "sync-sig-no-tool.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-sig-3-response-signing")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckResponseSigning_RealDaemonWithTool_Passes(t *testing.T) {
	const domain = "sync-sig-with-tool.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	baseURL := table.get(domain)
	if err := d.RegisterTool(baseURL, daemon.Tool{
		Manifest: &manifest.Manifest{
			Awp: "0.1", Name: domain + "#echo", Kind: "tool", Version: "1.0.0",
			Description:  "test",
			Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
			State:        "stateless",
			Auth:         manifest.Auth{Sig: "required"},
			Pricing:      json.RawMessage("null"),
		},
		Handler: func(_ context.Context, caller string, _ []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
			return json.RawMessage(`{"ok":true}`), nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-sig-3-response-signing")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass (internal/daemon now signs its responses)", r.Status, r.Detail)
	}
}

// TestCheckResponseSigning_InvalidSignature_Fails hand-builds a target (not
// a real daemon.Daemon) that signs its sync response and then corrupts the
// signature — a present-but-invalid signature, which awp-sig §3 requires
// rejecting outright, unlike an absent one.
func TestCheckResponseSigning_InvalidSignature_Fails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const domain = "sync-sig-invalid.example.com"
	const rfc3339Milli = "2006-01-02T15:04:05.000Z"
	now := time.Now()

	// The manifest's endpoint (and so its own bytes, and so the index's
	// sha256 pin on those bytes) all depend on the server's own URL, which
	// doesn't exist until httptest.NewServer returns — so everything
	// signed here is finalized after the server starts, and the handlers
	// below serve those precomputed bytes rather than building them
	// per-request.
	var idxBytes, manifestBytes []byte

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/awp.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(idxBytes)
	})
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(manifestBytes)
	})
	mux.HandleFunc("/call", func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`{"output":{"ok":true}}`)
		resp := &http.Response{StatusCode: 200, Header: http.Header{}}
		if err := httpsig.SignResponse(resp, body, priv, domain+"/k1", now); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// Corrupt the signature: still well-formed base64url, wrong
		// bytes — present-but-invalid, not absent.
		sigHeader := resp.Header.Get("Signature")
		inner := strings.TrimSuffix(strings.TrimPrefix(sigHeader, "awp=:"), ":")
		rawSig, err := base64.RawURLEncoding.DecodeString(inner)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rawSig[0] ^= 0xFF
		resp.Header.Set("Signature", "awp=:"+base64.RawURLEncoding.EncodeToString(rawSig)+":")
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := &manifest.Manifest{
		Awp: "0.1", Name: domain + "#tool", Kind: "tool", Version: "1.0.0",
		Distribution: manifest.Distribution{Hosted: &manifest.Hosted{Endpoint: srv.URL + "/call"}},
		State:        "stateless", Auth: manifest.Auth{Sig: "required"}, Pricing: json.RawMessage("null"),
	}
	if err := m.Sign(priv, "k1"); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	manifestBytes, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sum := sha256.Sum256(manifestBytes)

	idx := &identity.Index{
		Awp: "0.1", Domain: domain, Updated: now.UTC().Format(rfc3339Milli),
		Keys: []identity.Key{{Kid: "k1", Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub), Created: now.UTC().Format(rfc3339Milli)}},
		Entities: []identity.Entity{{
			Name: domain + "#tool", Kind: "tool",
			Manifest: srv.URL + "/manifest.json", ManifestSha256: hex.EncodeToString(sum[:]),
		}},
	}
	if err := idx.Sign(priv, "k1"); err != nil {
		t.Fatalf("sign index: %v", err)
	}
	idxBytes, err = json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}

	report := Run(context.Background(), domain, Options{
		BaseURL:      func(string) string { return srv.URL },
		HTTP:         srv.Client(),
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-sig-3-response-signing")
	if r.Status != Fail {
		t.Fatalf("status=%s detail=%s, want Fail (present-but-invalid signature)", r.Status, r.Detail)
	}
}

func TestCheckStatusEntity_NoStatusEntity_Skips(t *testing.T) {
	const domain = "status-entity-none.example.com"
	_, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-kinds-2-status-entity")
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckStatusEntity_RealDaemonWithStatusEntity_Passes(t *testing.T) {
	const domain = "status-entity-present.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	baseURL := table.get(domain)
	if err := d.RegisterTool(baseURL, daemon.Tool{
		Manifest: &manifest.Manifest{
			Awp: "0.1", Name: domain + "#health", Kind: "status", Version: "1.0.0",
			Description:  "test status entity",
			Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
			State:        "stateless",
			Auth:         manifest.Auth{Sig: "required"},
			Pricing:      json.RawMessage("null"),
		},
		Handler: func(_ context.Context, caller string, _ []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
			out, err := json.Marshal(map[string]any{
				"healthy":    true,
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			})
			if err != nil {
				return nil, &apperr.Error{Code: apperr.CodeInternal, Detail: err.Error()}
			}
			return out, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-kinds-2-status-entity")
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass", r.Status, r.Detail)
	}
}

func TestCheckStatusEntity_MalformedResponse_Fails(t *testing.T) {
	const domain = "status-entity-malformed.example.com"
	d, priv, table, httpClient := newTargetDaemon(t, domain, "k1", false)

	baseURL := table.get(domain)
	if err := d.RegisterTool(baseURL, daemon.Tool{
		Manifest: &manifest.Manifest{
			Awp: "0.1", Name: domain + "#health", Kind: "status", Version: "1.0.0",
			Description:  "test status entity that forgets healthy",
			Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
			State:        "stateless",
			Auth:         manifest.Auth{Sig: "required"},
			Pricing:      json.RawMessage("null"),
		},
		Handler: func(_ context.Context, caller string, _ []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
			return json.RawMessage(`{"detail":"no healthy field at all"}`), nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	report := Run(context.Background(), domain, Options{
		BaseURL: baseURLOpt(table), HTTP: httpClient,
		CallerDomain: domain, CallerKid: "k1", CallerPriv: priv,
	})
	r := getCheck(t, report, "awp-kinds-2-status-entity")
	if r.Status != Fail {
		t.Fatalf("status=%s detail=%s, want Fail (missing healthy field)", r.Status, r.Detail)
	}
}
