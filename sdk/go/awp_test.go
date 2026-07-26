package awp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/store"
)

// fakeDaemonResolver is the Resolver a test daemon needs: it resolves the
// SDK client's own signing key (preloaded by the test) and never needs
// outbound inbox/transport discovery in these tests, since the daemon
// under test never originates its own outbound sends here.
type fakeDaemonResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *fakeDaemonResolver) add(domain, kid string, pub ed25519.PublicKey) {
	if r.keys == nil {
		r.keys = map[string]ed25519.PublicKey{}
	}
	r.keys[domain+"/"+kid] = pub
}

func (r *fakeDaemonResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}

func (r *fakeDaemonResolver) Refresh(string) error                { return nil }
func (r *fakeDaemonResolver) ResolveInbox(string) (string, error) { return "", nil }
func (r *fakeDaemonResolver) ResolveTransport(string, string) (string, bool, error) {
	return "", false, nil
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func newTestDaemon(t *testing.T, domain string, resolver *fakeDaemonResolver) (*daemon.Daemon, *httptest.Server) {
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
	d, err := daemon.New(daemon.Config{
		Domain: domain, Kid: "k1", Priv: priv, Store: st,
		Clock: clock.NewFixed(time.Now()), Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		t.Fatalf("FinalizeIndex: %v", err)
	}
	return d, srv
}

// clientForDaemon returns an SDK Client whose IndexURL resolves domain to
// srv's own /.well-known/awp.json — standing in for real DNS+HTTPS, which
// httptest.Server can't provide.
func clientForDaemon(domain string, priv ed25519.PrivateKey, kid string, srvsByDomain map[string]*httptest.Server) *Client {
	return &Client{
		Domain: domain, Kid: kid, Priv: priv,
		IndexURL: func(d string) string {
			srv, ok := srvsByDomain[d]
			if !ok {
				return "https://" + d + "/.well-known/awp.json"
			}
			return srv.URL + "/.well-known/awp.json"
		},
	}
}

func TestSendEnvelope_DeliversToRealDaemonInbox(t *testing.T) {
	senderPub, senderPriv := mustKeypair(t)

	recvResolver := &fakeDaemonResolver{}
	recvResolver.add("sender.example.com", "sk1", senderPub)
	recvDaemon, recvSrv := newTestDaemon(t, "recipient.example.com", recvResolver)

	c := clientForDaemon("sender.example.com", senderPriv, "sk1", map[string]*httptest.Server{
		"recipient.example.com": recvSrv,
	})

	sentEnv, err := c.SendEnvelope(context.Background(), "message", "recipient.example.com#agent", envelope.NewID(), nil, json.RawMessage(`{"text":"hi"}`), 3600)
	if err != nil {
		t.Fatalf("SendEnvelope: %v", err)
	}
	if sentEnv.From != "sender.example.com" {
		t.Fatalf("From = %q", sentEnv.From)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := recvDaemon.ProcessInboundOnce(context.Background())
		if err != nil {
			t.Fatalf("ProcessInboundOnce: %v", err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("recipient never processed the delivered envelope")
}

func TestSendEnvelope_RejectsOversizeTTL(t *testing.T) {
	pub, priv := mustKeypair(t)
	_ = pub
	c := &Client{Domain: "sender.example.com", Kid: "sk1", Priv: priv}
	_, err := c.SendEnvelope(context.Background(), "message", "recipient.example.com#agent", envelope.NewID(), nil, json.RawMessage(`{}`), 999999999)
	if err == nil {
		t.Fatal("expected a ttl-out-of-bounds error")
	}
}

func statelessManifest(name string) *manifest.Manifest {
	return &manifest.Manifest{
		Awp: "0.1", Name: name, Kind: "tool", Version: "1.0.0",
		Description:  "sdk test tool",
		Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
		State:        "stateless",
		Auth:         manifest.Auth{Sig: "required"},
		Pricing:      json.RawMessage("null"),
	}
}

func providerManifest(name string) *manifest.Manifest {
	m := statelessManifest(name)
	m.State = "provider"
	return m
}

func TestCallTool_StatelessHostedRoundTrip(t *testing.T) {
	callerPub, callerPriv := mustKeypair(t)

	toolResolver := &fakeDaemonResolver{}
	toolResolver.add("caller.example.com", "ck1", callerPub)
	toolDaemon, toolSrv := newTestDaemon(t, "tool.example.com", toolResolver)

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		var in struct {
			N int `json:"n"`
		}
		_ = json.Unmarshal(input, &in)
		out, err := json.Marshal(map[string]any{"caller": caller, "double": in.N * 2})
		if err != nil {
			return nil, &apperr.Error{Code: apperr.CodeInternal, Detail: err.Error()}
		}
		return out, nil
	}
	if err := toolDaemon.RegisterTool(toolSrv.URL, daemon.Tool{Manifest: statelessManifest("tool.example.com#doubler"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	c := clientForDaemon("caller.example.com", callerPriv, "ck1", map[string]*httptest.Server{
		"tool.example.com": toolSrv,
	})

	output, session, err := c.CallTool(context.Background(), "tool.example.com#doubler", json.RawMessage(`{"n":21}`), CallOptions{})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if session != nil {
		t.Fatalf("expected no session from a stateless tool, got %+v", session)
	}
	var out struct {
		Caller string `json:"caller"`
		Double int    `json:"double"`
	}
	if err := json.Unmarshal(output, &out); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if out.Caller != "caller.example.com" || out.Double != 42 {
		t.Fatalf("output = %+v", out)
	}
}

func TestCallTool_ProviderSessionLifecycle(t *testing.T) {
	callerPub, callerPriv := mustKeypair(t)

	toolResolver := &fakeDaemonResolver{}
	toolResolver.add("caller.example.com", "ck1", callerPub)
	toolDaemon, toolSrv := newTestDaemon(t, "tool.example.com", toolResolver)

	calls := 0
	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		calls++
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := toolDaemon.RegisterTool(toolSrv.URL, daemon.Tool{Manifest: providerManifest("tool.example.com#stateful"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	c := clientForDaemon("caller.example.com", callerPriv, "ck1", map[string]*httptest.Server{
		"tool.example.com": toolSrv,
	})

	_, session, err := c.CallTool(context.Background(), "tool.example.com#stateful", json.RawMessage(`{}`), CallOptions{})
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	if session == nil || session.Token == "" {
		t.Fatalf("expected a session from a provider tool's first call, got %+v", session)
	}

	_, session2, err := c.CallTool(context.Background(), "tool.example.com#stateful", json.RawMessage(`{}`), CallOptions{Session: session.Token})
	if err != nil {
		t.Fatalf("second CallTool with session: %v", err)
	}
	if session2 != nil {
		t.Fatalf("expected no re-issued session on an authenticated repeat call, got %+v", session2)
	}
	if calls != 2 {
		t.Fatalf("handler called %d times, want 2", calls)
	}
}

func TestCallTool_HandlerErrorSurfacesAsError(t *testing.T) {
	callerPub, callerPriv := mustKeypair(t)

	toolResolver := &fakeDaemonResolver{}
	toolResolver.add("caller.example.com", "ck1", callerPub)
	toolDaemon, toolSrv := newTestDaemon(t, "tool.example.com", toolResolver)

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return nil, &apperr.Error{Code: apperr.CodeRefused, Detail: "no thanks", Retryable: false}
	}
	if err := toolDaemon.RegisterTool(toolSrv.URL, daemon.Tool{Manifest: statelessManifest("tool.example.com#grumpy"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	c := clientForDaemon("caller.example.com", callerPriv, "ck1", map[string]*httptest.Server{
		"tool.example.com": toolSrv,
	})

	_, _, err := c.CallTool(context.Background(), "tool.example.com#grumpy", json.RawMessage(`{}`), CallOptions{})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestCallTool_UnsignedCallerRejected(t *testing.T) {
	// Recipient never learned the caller's key at all — Resolve fails
	// server-side and the call is rejected, proving the SDK doesn't
	// somehow bypass signature verification on the wire.
	_, callerPriv := mustKeypair(t)

	toolResolver := &fakeDaemonResolver{} // deliberately empty
	toolDaemon, toolSrv := newTestDaemon(t, "tool.example.com", toolResolver)

	handler := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		return json.RawMessage(`{"ok":true}`), nil
	}
	if err := toolDaemon.RegisterTool(toolSrv.URL, daemon.Tool{Manifest: statelessManifest("tool.example.com#echo"), Handler: handler}); err != nil {
		t.Fatalf("RegisterTool: %v", err)
	}

	c := clientForDaemon("caller.example.com", callerPriv, "ck1", map[string]*httptest.Server{
		"tool.example.com": toolSrv,
	})

	_, _, err := c.CallTool(context.Background(), "tool.example.com#echo", json.RawMessage(`{}`), CallOptions{})
	if err == nil {
		t.Fatal("expected an error for an unresolvable caller key")
	}
}

func TestSignDelegationLink_ProducesVerifiableLink(t *testing.T) {
	_, delegatorPriv := mustKeypair(t)
	c := &Client{Domain: "delegator.example.com", Kid: "dk1", Priv: delegatorPriv}
	to := "tool.example.com#doubler"
	link, err := c.SignDelegationLink("delegate.example.com", delegation.Scope{To: &to}, time.Now().Add(time.Hour), envelope.NewID())
	if err != nil {
		t.Fatalf("SignDelegationLink: %v", err)
	}
	if link.Delegator != "delegator.example.com" || link.Delegate != "delegate.example.com" {
		t.Fatalf("link = %+v", link)
	}
	if link.Sig == nil {
		t.Fatal("expected a signature")
	}
}

func TestFetchIndex_CachesAcrossCalls(t *testing.T) {
	resolver := &fakeDaemonResolver{}
	_, srv := newTestDaemon(t, "example.com", resolver)
	c := &Client{IndexURL: func(string) string { return srv.URL + "/.well-known/awp.json" }}

	idx1, err := c.FetchIndex(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("FetchIndex: %v", err)
	}
	idx2, err := c.FetchIndex(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("FetchIndex (cached): %v", err)
	}
	if idx1 != idx2 {
		t.Fatal("expected the second FetchIndex to return the cached pointer")
	}
}
