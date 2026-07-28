package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/store"
	"github.com/agentask/awp/internal/wasmrt"
)

// toolFakeResolver is a KeyResolver a test can populate with arbitrary
// (domain, kid) -> pubkey entries, standing in for real HTTP index
// resolution when testing the tool-serving endpoint's own logic.
type toolFakeResolver struct {
	keys map[string]ed25519.PublicKey
}

func newToolFakeResolver() *toolFakeResolver {
	return &toolFakeResolver{keys: map[string]ed25519.PublicKey{}}
}

func (r *toolFakeResolver) add(domain, kid string, pub ed25519.PublicKey) {
	r.keys[domain+"/"+kid] = pub
}

func (r *toolFakeResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}

func (r *toolFakeResolver) Refresh(string) error                { return nil }
func (r *toolFakeResolver) ResolveInbox(string) (string, error) { return "", nil }
func (r *toolFakeResolver) ResolveTransport(string, string) (string, bool, error) {
	return "", false, nil
}

func (r *toolFakeResolver) ResolveWake(string) (string, bool, error) {
	return "", false, nil
}

// newToolTestDaemon builds a Daemon backed by a resolver the test can add
// caller keys to, for exercising the tool-serving endpoint directly.
func newToolTestDaemon(t *testing.T, domain string, clk clock.Clock) (*Daemon, *toolFakeResolver) {
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
	resolver := newToolFakeResolver()
	d, err := New(Config{Domain: domain, Kid: "k1", Priv: priv, Store: st, Clock: clk, Resolver: resolver})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, resolver
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func signedToolRequest(t *testing.T, method, url string, body []byte, priv ed25519.PrivateKey, keyID string, now time.Time, extraHeaders map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if err := httpsig.Sign(req, body, priv, keyID, now); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func statelessToolManifest(name string) *manifest.Manifest {
	return &manifest.Manifest{
		Awp: "0.1", Name: name, Kind: "tool", Version: "1.0.0",
		Description:  "test tool",
		Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
		State:        "stateless",
		Auth:         manifest.Auth{Sig: "required"},
		Pricing:      json.RawMessage("null"),
	}
}

func providerToolManifest(name string) *manifest.Manifest {
	m := statelessToolManifest(name)
	m.State = "provider"
	return m
}

func TestRegisterTool_ServesManifestWithCorrectPinning(t *testing.T) {
	d, _ := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(time.Now()))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	resp, err := http.Get(srv.URL + "/awp/manifests/echo.json")
	if err != nil {
		t.Fatalf("get manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read manifest body: %v", err)
	}

	sum := sha256.Sum256(raw)
	gotHash := hex.EncodeToString(sum[:])

	idxResp, err := http.Get(srv.URL + "/.well-known/awp.json")
	if err != nil {
		t.Fatalf("get index: %v", err)
	}
	defer idxResp.Body.Close()
	var idx struct {
		Entities []struct {
			Name           string `json:"name"`
			ManifestSha256 string `json:"manifest_sha256"`
			Manifest       string `json:"manifest"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(idxResp.Body).Decode(&idx); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	if len(idx.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(idx.Entities))
	}
	if idx.Entities[0].ManifestSha256 != gotHash {
		t.Fatalf("index pins %q, actual manifest hashes to %q", idx.Entities[0].ManifestSha256, gotHash)
	}
	if idx.Entities[0].Manifest != srv.URL+"/awp/manifests/echo.json" {
		t.Fatalf("unexpected manifest URL: %s", idx.Entities[0].Manifest)
	}
}

func TestServeToolCall_HostedStatelessSuccess(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	var gotCaller string
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		gotCaller = caller
		return json.RawMessage(`{"doubled":2}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{"x":1}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var out syncSuccessBody
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(out.Output) != `{"doubled":2}` {
		t.Fatalf("output = %s", out.Output)
	}
	if out.Session != nil {
		t.Fatal("expected no session for a stateless tool")
	}
	if gotCaller != "caller.example.com" {
		t.Fatalf("handler saw caller = %q, want caller.example.com", gotCaller)
	}
}

// TestServeToolCall_DryRunHeaderReachesHandler covers awp-capabilities-v0.1.md
// §3.1: AWP-Dry-Run is an ordinary AWP-* header (no httpsig change needed
// to cover it in the signature) and serveToolCall threads it through to
// the handler via daemon.IsDryRun, not a ToolHandler signature change.
func TestServeToolCall_DryRunHeaderReachesHandler(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	var gotDryRun bool
	m := statelessToolManifest("provider.example.com#echo")
	m.Capabilities = []string{manifest.DryRunCapability}
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		gotDryRun = IsDryRun(ctx)
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: m, Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now,
		map[string]string{"AWP-Dry-Run": "true"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if !gotDryRun {
		t.Fatal("expected the handler to observe IsDryRun(ctx) == true")
	}
}

func TestServeToolCall_NoDryRunHeaderMeansNotDryRun(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	var gotDryRun bool
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		gotDryRun = IsDryRun(ctx)
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotDryRun {
		t.Fatal("expected IsDryRun(ctx) == false when the header is absent")
	}
}

// TestServeToolCall_TransactionHeaderReachesHandler covers
// awp-transactions-v0.1.md §2: AWP-Transaction is an ordinary AWP-*
// header (no httpsig change needed) and serveToolCall threads it through
// to the handler via daemon.TransactionFromContext.
func TestServeToolCall_TransactionHeaderReachesHandler(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	var gotTxn *Transaction
	var gotOK bool
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		gotTxn, gotOK = TransactionFromContext(ctx)
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	header := encodeTransactionHeader(t, Transaction{ID: "01hxxx", Step: 2, Coordinator: "caller.example.com"})
	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now,
		map[string]string{"AWP-Transaction": header})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if !gotOK {
		t.Fatal("expected TransactionFromContext to report ok=true")
	}
	if gotTxn.ID != "01hxxx" || gotTxn.Step != 2 || gotTxn.Coordinator != "caller.example.com" {
		t.Fatalf("got %+v, want {ID:01hxxx Step:2 Coordinator:caller.example.com}", gotTxn)
	}
}

func TestServeToolCall_NoTransactionHeaderMeansNoTransaction(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	var gotOK bool
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		_, gotOK = TransactionFromContext(ctx)
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotOK {
		t.Fatal("expected TransactionFromContext ok=false when the header is absent")
	}
}

func TestServeToolCall_MalformedTransactionHeader_Rejected(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		t.Fatal("handler must not be invoked for a malformed AWP-Transaction header")
		return nil, nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	tests := []struct {
		name   string
		header string
	}{
		{"not valid base64url", "not-valid-base64url!!!"},
		{"valid base64url, not JSON", base64.RawURLEncoding.EncodeToString([]byte("not json"))},
		{"valid JSON, missing id", base64.RawURLEncoding.EncodeToString([]byte(`{"step":0}`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{}`)
			req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now,
				map[string]string{"AWP-Transaction": tt.header})
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 400 {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, body = %s, want 400", resp.StatusCode, raw)
			}
		})
	}
}

func encodeTransactionHeader(t *testing.T, txn Transaction) string {
	t.Helper()
	raw, err := json.Marshal(txn)
	if err != nil {
		t.Fatalf("marshal transaction: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestServeToolCall_RejectsBadSignature(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, _ := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		t.Fatal("handler must not run when signature verification fails")
		return nil, nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	// Never registered with the resolver: an unknown signer.
	_, unknownPriv := mustKeypair(t)
	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, unknownPriv, "nobody.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var body2 apperr.Body
	if err := json.NewDecoder(resp.Body).Decode(&body2); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body2.Error == nil || body2.Error.Code != apperr.CodeUnauthorized {
		t.Fatalf("expected code=unauthorized, got %+v", body2.Error)
	}
}

func TestServeToolCall_HandlerErrorMapsToStatus(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return nil, &apperr.Error{Code: apperr.CodeRefused, Detail: "totals too large", Retryable: false}
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: statelessToolManifest("provider.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/echo", body, callerPriv, "caller.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var errBody apperr.Body
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errBody.Error == nil || errBody.Error.Code != apperr.CodeRefused {
		t.Fatalf("expected code=refused, got %+v", errBody.Error)
	}
}

// core §1.3: the first sync call to a `state: provider` tool returns a
// session; a subsequent call presenting that session succeeds without a
// new one being issued.
func TestServeToolCall_ProviderSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: providerToolManifest("provider.example.com#stateful"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}
	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{}`)
	req1 := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/stateful", body, callerPriv, "caller.example.com/k1", now, nil)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("Do 1: %v", err)
	}
	defer resp1.Body.Close()
	var out1 syncSuccessBody
	if err := json.NewDecoder(resp1.Body).Decode(&out1); err != nil {
		t.Fatalf("decode 1: %v", err)
	}
	if out1.Session == nil {
		t.Fatal("expected a session on the first call to a provider tool")
	}

	req2 := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/stateful", body, callerPriv, "caller.example.com/k1", now.Add(time.Second),
		map[string]string{"AWP-Session": out1.Session.Token})
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Do 2: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("status = %d, body = %s", resp2.StatusCode, raw)
	}
	var out2 syncSuccessBody
	if err := json.NewDecoder(resp2.Body).Decode(&out2); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	if out2.Session != nil {
		t.Fatal("expected no new session issued when a valid one was already presented")
	}
}

func TestServeToolCall_ProviderRejectsSessionForDifferentCaller(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: providerToolManifest("provider.example.com#stateful"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	pubA, privA := mustKeypair(t)
	resolver.add("a.example.com", "k1", pubA)
	pubB, privB := mustKeypair(t)
	resolver.add("b.example.com", "k1", pubB)

	body := []byte(`{}`)
	reqA := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/stateful", body, privA, "a.example.com/k1", now, nil)
	respA, err := http.DefaultClient.Do(reqA)
	if err != nil {
		t.Fatalf("Do A: %v", err)
	}
	defer respA.Body.Close()
	var outA syncSuccessBody
	if err := json.NewDecoder(respA.Body).Decode(&outA); err != nil {
		t.Fatalf("decode A: %v", err)
	}

	// B tries to use A's session — core §1.3: "sessions do not transfer."
	reqB := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/stateful", body, privB, "b.example.com/k1", now.Add(time.Second),
		map[string]string{"AWP-Session": outA.Session.Token})
	respB, err := http.DefaultClient.Do(reqB)
	if err != nil {
		t.Fatalf("Do B: %v", err)
	}
	defer respB.Body.Close()
	if respB.StatusCode != 401 {
		t.Fatalf("status = %d, want 401 (session must not transfer between callers)", respB.StatusCode)
	}
}

func buildTestWasmForDaemon(t *testing.T, sourcePath string) []byte {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "mod.wasm")
	cmd := exec.Command("go", "build", "-o", outPath, sourcePath)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", sourcePath, err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read %s: %v", outPath, err)
	}
	return data
}

func TestServeToolCall_PortableWasmSuccess(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, resolver := newToolTestDaemon(t, "provider.example.com", clock.NewFixed(now))
	srv := httptest.NewServer(d)
	defer srv.Close()

	wasmBytes := buildTestWasmForDaemon(t, "testdata/echo/main.go")
	sum := sha256.Sum256(wasmBytes)
	mod, err := wasmrt.Compile(context.Background(), wasmBytes, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("wasmrt.Compile: %v", err)
	}
	t.Cleanup(func() { _ = mod.Close(context.Background()) })

	m := statelessToolManifest("provider.example.com#wasm-echo")
	m.Distribution = manifest.Distribution{Portable: &manifest.Portable{
		URL: "unused-in-this-test", Sha256: hex.EncodeToString(sum[:]), Runtime: "wasm32-wasip1", Interface: "stdio-json/1",
	}}
	if err := d.RegisterTool(srv.URL, Tool{Manifest: m, Module: mod}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	callerPub, callerPriv := mustKeypair(t)
	resolver.add("caller.example.com", "k1", callerPub)

	body := []byte(`{"y":2}`)
	req := signedToolRequest(t, http.MethodPost, srv.URL+"/awp/tools/wasm-echo", body, callerPriv, "caller.example.com/k1", now, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var out syncSuccessBody
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var echoed struct {
		EchoedCaller string `json:"echoed_caller"`
	}
	if err := json.Unmarshal(out.Output, &echoed); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if echoed.EchoedCaller != "caller.example.com" {
		t.Fatalf("echoed_caller = %q, want caller.example.com", echoed.EchoedCaller)
	}
}
