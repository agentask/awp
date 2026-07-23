package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/delegation"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

type fakeResolver struct {
	keys      map[string]ed25519.PublicKey
	refreshed []string
}

func newFakeResolver() *fakeResolver { return &fakeResolver{keys: map[string]ed25519.PublicKey{}} }

func (f *fakeResolver) add(domain, kid string, pub ed25519.PublicKey) {
	f.keys[domain+"/"+kid] = pub
}

func (f *fakeResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := f.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}

func (f *fakeResolver) Refresh(domain string) error {
	f.refreshed = append(f.refreshed, domain)
	return nil
}

func newRequest(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func TestSignVerify_RoundTrip_BodylessGET(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("caller.example.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	req := newRequest(t, http.MethodGet, "https://example.com/awp/tools/generate-invoice", nil)
	if err := Sign(req, nil, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if req.Header.Get("Content-Digest") != "" {
		t.Fatal("bodyless GET must not carry a Content-Digest")
	}

	result := Verify(req, nil, now, Deps{ResolveKey: resolver})
	if result.Err != nil {
		t.Fatalf("Verify: %+v", result.Err)
	}
	if result.CallerPrincipal != "caller.example.com" {
		t.Fatalf("caller = %q, want caller.example.com", result.CallerPrincipal)
	}
}

func TestSignVerify_RoundTrip_POSTWithBody(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("caller.example.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"amount":100}`)

	req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/generate-invoice", body)
	if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if req.Header.Get("Content-Digest") == "" {
		t.Fatal("POST with body must carry a Content-Digest")
	}

	result := Verify(req, body, now, Deps{ResolveKey: resolver})
	if result.Err != nil {
		t.Fatalf("Verify: %+v", result.Err)
	}
}

func TestSignVerify_RoundTrip_POSTWithSession(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("caller.example.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	body := []byte(`{}`)

	req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/generate-invoice", body)
	req.Header.Set("AWP-Session", "session-token-xyz") // must be set before Sign so it's covered
	if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	var verifiedCaller, verifiedToken string
	deps := Deps{
		ResolveKey: resolver,
		VerifySession: func(token, caller string) error {
			verifiedToken, verifiedCaller = token, caller
			return nil
		},
	}
	result := Verify(req, body, now, deps)
	if result.Err != nil {
		t.Fatalf("Verify: %+v", result.Err)
	}
	if !result.HasSession {
		t.Fatal("expected HasSession=true")
	}
	if verifiedToken != "session-token-xyz" || verifiedCaller != "caller.example.com" {
		t.Fatalf("VerifySession called with (%q, %q)", verifiedToken, verifiedCaller)
	}
}

// build2LinkDelegationChain returns a valid 2-link chain ending in
// delegate == callerDomain (bare, matching what a sync call's keyid can
// express), scoped `to` target. relayEntity's domain MUST equal
// callerDomain (the relay is a sub-identity of the same operator that
// signs the actual request) — so the second link is signed with
// callerPriv, the SAME domain key the outer request itself uses; a
// separately generated "relay" keypair for that domain would collide with
// (and silently overwrite) the resolver's entry for the real signing key.
func build2LinkDelegationChain(t *testing.T, resolver *fakeResolver, rootDomain, relayEntity, callerDomain string, callerPriv ed25519.PrivateKey, target string, now time.Time) []delegation.Link {
	t.Helper()
	_, rootPriv := mustKeypair(t)
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	resolver.add(rootDomain, "k1", rootPub)

	root := delegation.Link{
		Delegator: rootDomain,
		Delegate:  relayEntity,
		Scope:     delegation.Scope{To: &target},
		Expires:   now.Add(time.Hour).Format(time.RFC3339),
		Nonce:     "01arz3ndektsv4rrffq69g5fav",
	}
	if err := root.Sign(rootPriv, "k1"); err != nil {
		t.Fatalf("sign root link: %v", err)
	}
	second := delegation.Link{
		Delegator: relayEntity,
		Delegate:  callerDomain,
		Scope:     delegation.Scope{},
		Expires:   now.Add(time.Hour).Format(time.RFC3339),
		Nonce:     "01arz3ndektsv4rrffq69g5fbv",
	}
	if err := second.Sign(callerPriv, "k1"); err != nil {
		t.Fatalf("sign second link: %v", err)
	}
	return []delegation.Link{root, second}
}

func TestSignVerify_RoundTrip_POSTWithDelegation(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("assistant.acme.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	const target = "provider.example.com#tool"

	chain := build2LinkDelegationChain(t, resolver, "user-root.example.com", "assistant.acme.com#relay", "assistant.acme.com", priv, target, now)
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	delHeader := base64.RawURLEncoding.EncodeToString(chainJSON)

	body := []byte(`{}`)
	req := newRequest(t, http.MethodPost, "https://provider.example.com/awp/tools/tool", body)
	req.Header.Set("AWP-Delegation", delHeader)
	if err := Sign(req, body, priv, "assistant.acme.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result := Verify(req, body, now, Deps{ResolveKey: resolver, Target: target})
	if result.Err != nil {
		t.Fatalf("Verify: %+v", result.Err)
	}
	if len(result.Delegation) != 2 {
		t.Fatalf("expected a 2-link delegation chain in the result, got %d", len(result.Delegation))
	}
}

// EARS gate: every awp-sig §2 failure mode rejects with the specific
// status/code the spec assigns that step, and steps are checked in order
// (a later-step problem must not surface if an earlier step already fails).
func TestVerify_EachFailureModeInIsolation(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	newValidPOST := func(t *testing.T, resolver *fakeResolver) (*http.Request, []byte, ed25519.PrivateKey) {
		pub, priv := mustKeypair(t)
		resolver.add("caller.example.com", "k1", pub)
		body := []byte(`{"hello":"world"}`)
		req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/tool", body)
		if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return req, body, priv
	}

	tests := []struct {
		name       string
		mutate     func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte
		wantStatus int
		wantCode   string
	}{
		{
			name: "step1: missing Signature-Input",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				req.Header.Del("Signature-Input")
				return body
			},
			wantStatus: 400, wantCode: apperr.CodeMalformed,
		},
		{
			name: "step1: unknown label",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				req.Header.Set("Signature-Input", `other=("@method" "@target-uri" "content-digest");created=1753088043;keyid="caller.example.com/k1";alg="ed25519"`)
				return body
			},
			wantStatus: 400, wantCode: apperr.CodeMalformed,
		},
		{
			name: "step1: forbidden param (expires)",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				v := req.Header.Get("Signature-Input")
				req.Header.Set("Signature-Input", v+";expires=1753089000")
				return body
			},
			wantStatus: 400, wantCode: apperr.CodeMalformed,
		},
		{
			name: "step1: missing covered component (dropped content-digest)",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				req.Header.Set("Signature-Input", `awp=("@method" "@target-uri");created=1753088043;keyid="caller.example.com/k1";alg="ed25519"`)
				return body
			},
			wantStatus: 400, wantCode: apperr.CodeMalformed,
		},
		{
			name: "step2: created outside +-300s window",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				parsed, err := ParseSignatureInput(req.Header.Get("Signature-Input"))
				if err != nil {
					t.Fatalf("re-parse: %v", err)
				}
				parsed.Params.Created = now.Add(-time.Hour).Unix()
				req.Header.Set("Signature-Input", parsed.Params.HeaderValue())
				return body
			},
			wantStatus: 401, wantCode: apperr.CodeUnauthorized,
		},
		{
			name: "step3: content-digest mismatch (fires before step5's signature check)",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				req.Header.Set("Content-Digest", "sha-256=:deadbeef00000000000000000000000000000000000000000000000000==:")
				return body
			},
			wantStatus: 400, wantCode: apperr.CodeMalformed,
		},
		{
			name: "step4: unknown key",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				delete(resolver.keys, "caller.example.com/k1")
				return body
			},
			wantStatus: 401, wantCode: apperr.CodeUnauthorized,
		},
		{
			name: "step5: bad signature (target URI tampered post-signing)",
			mutate: func(t *testing.T, req *http.Request, body []byte, resolver *fakeResolver) []byte {
				req.URL.Path = "/awp/tools/some-other-tool"
				return body
			},
			wantStatus: 401, wantCode: apperr.CodeUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newFakeResolver()
			req, body, _ := newValidPOST(t, resolver)
			body = tt.mutate(t, req, body, resolver)

			result := Verify(req, body, now, Deps{ResolveKey: resolver})
			if result.Err == nil {
				t.Fatalf("expected a failure, got success: %+v", result)
			}
			if result.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d (detail: %s)", result.Status, tt.wantStatus, result.Err.Detail)
			}
			if result.Err.Code != tt.wantCode {
				t.Fatalf("code = %q, want %q", result.Err.Code, tt.wantCode)
			}
		})
	}
}

func TestVerify_Step6_DelegationFailure(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("assistant.acme.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	const target = "provider.example.com#tool"

	chain := build2LinkDelegationChain(t, resolver, "user-root.example.com", "assistant.acme.com#relay", "assistant.acme.com", priv, target, now)
	// Break the chain: final delegate no longer matches the caller
	// (tamper AFTER building, so the link's own signature is now invalid
	// too — but that's fine, delegation link signature failure IS one of
	// the core §2.5 rules step 6 is responsible for surfacing as 403).
	chain[1].Delegate = "someone-else.example.com"
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	delHeader := base64.RawURLEncoding.EncodeToString(chainJSON)

	body := []byte(`{}`)
	req := newRequest(t, http.MethodPost, "https://provider.example.com/awp/tools/tool", body)
	req.Header.Set("AWP-Delegation", delHeader)
	if err := Sign(req, body, priv, "assistant.acme.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result := Verify(req, body, now, Deps{ResolveKey: resolver, Target: target})
	if result.Err == nil {
		t.Fatal("expected a delegation failure")
	}
	if result.Status != 403 {
		t.Fatalf("status = %d, want 403", result.Status)
	}
	if result.Err.Code != apperr.CodeUnauthorizedDelegation {
		t.Fatalf("code = %q, want %q", result.Err.Code, apperr.CodeUnauthorizedDelegation)
	}
}

func TestVerify_Step7_SessionFailure(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("caller.example.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	body := []byte(`{}`)

	req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/tool", body)
	req.Header.Set("AWP-Session", "bad-token")
	if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	deps := Deps{
		ResolveKey:    resolver,
		VerifySession: func(token, caller string) error { return fmt.Errorf("invalid") },
	}
	result := Verify(req, body, now, deps)
	if result.Err == nil {
		t.Fatal("expected a session failure")
	}
	if result.Status != 401 {
		t.Fatalf("status = %d, want 401", result.Status)
	}
}

func TestVerify_Step7_NoVerifierConfiguredRejectsSession(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("caller.example.com", "k1", pub)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	body := []byte(`{}`)

	req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/tool", body)
	req.Header.Set("AWP-Session", "any-token")
	if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result := Verify(req, body, now, Deps{ResolveKey: resolver})
	if result.Err == nil || result.Status != 401 {
		t.Fatalf("expected 401 for a session on an endpoint with no VerifySession configured, got %+v", result)
	}
}

// core §0.1 rotation-race: one refresh attempted before hard-failing.
func TestVerify_Step4_RefreshAttemptedOnceOnKeyResolveFailure(t *testing.T) {
	_, priv := mustKeypair(t)
	resolver := newFakeResolver()
	// Deliberately don't register the key up front.
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	body := []byte(`{}`)
	req := newRequest(t, http.MethodPost, "https://example.com/awp/tools/tool", body)
	if err := Sign(req, body, priv, "caller.example.com/k1", now); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result := Verify(req, body, now, Deps{ResolveKey: resolver})
	if result.Status != 401 {
		t.Fatalf("status = %d, want 401", result.Status)
	}
	if len(resolver.refreshed) != 1 || resolver.refreshed[0] != "caller.example.com" {
		t.Fatalf("expected exactly one refresh of caller.example.com, got %v", resolver.refreshed)
	}
}
