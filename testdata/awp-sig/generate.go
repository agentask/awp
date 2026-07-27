// Command generate produces the testdata/awp-sig/ conformance vectors
// required by CLAUDE.md's Phase 5 ("Generate testdata/awp-sig/ vectors ...
// double as cross-implementation conformance fixtures"). Run it with:
//
//	go run testdata/awp-sig/generate.go
//
// Files inside a directory literally named "testdata" are never part of
// any Go package the toolchain discovers via "./..." patterns, so this
// file needs no build tag to stay out of `go build`/`go vet`/`go test`.
//
// Every vector is self-checked against this repo's own httpsig.Verify
// before being written, so a vector that wouldn't actually round-trip
// through the reference implementation can never ship.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/httpsig"
)

type vector struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	Domain         string            `json:"domain"`
	Kid            string            `json:"kid"`
	PrivateKeySeed string            `json:"private_key_seed_b64url"`
	PublicKey      string            `json:"public_key_b64url"`
	Method         string            `json:"method"`
	TargetURI      string            `json:"target_uri"`
	BodyB64        *string           `json:"body_b64url"`
	ExtraHeaders   map[string]string `json:"extra_headers,omitempty"`
	Created        int64             `json:"created"`
	VerifyAt       string            `json:"verify_at"`
	SignatureInput string            `json:"signature_input"`
	Signature      string            `json:"signature"`
	ContentDigest  *string           `json:"content_digest,omitempty"`
	SignatureBase  string            `json:"signature_base"`
	// TrustedKeys are additional (domain, kid) -> pubkey entries a
	// verifier needs beyond the request's own signer — e.g. a delegation
	// chain's root signer. Structured on purpose: a cross-implementation
	// fixture must never require another implementation to regex a
	// free-text Note for load-bearing key material.
	TrustedKeys []trustedKey `json:"trusted_keys,omitempty"`
	// DelegationTarget is the principal a delegation chain's scope.to is
	// checked against, when AWP-Delegation is present.
	DelegationTarget string      `json:"delegation_target,omitempty"`
	Expect           expectation `json:"expect"`
	Note             string      `json:"note,omitempty"`
}

// responseVector is the response counterpart to vector — a distinct shape
// rather than overloading vector's request-only fields (method,
// target_uri) with values that don't apply to a response.
type responseVector struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	Domain         string      `json:"domain"`
	Kid            string      `json:"kid"`
	PrivateKeySeed string      `json:"private_key_seed_b64url"`
	PublicKey      string      `json:"public_key_b64url"`
	Status         int         `json:"status"`
	BodyB64        *string     `json:"body_b64url"`
	Created        int64       `json:"created"`
	VerifyAt       string      `json:"verify_at"`
	SignatureInput string      `json:"signature_input"`
	Signature      string      `json:"signature"`
	ContentDigest  *string     `json:"content_digest,omitempty"`
	SignatureBase  string      `json:"signature_base"`
	Expect         expectation `json:"expect"`
	Note           string      `json:"note,omitempty"`
}

type trustedKey struct {
	Domain string `json:"domain"`
	Kid    string `json:"kid"`
	PubKey string `json:"pub_b64url"`
}

type expectation struct {
	Status int    `json:"status"`
	Code   string `json:"code,omitempty"`
}

// staticResolver is the fixed single-key resolver every self-check
// verifies against.
type staticResolver struct {
	domain, kid string
	pub         ed25519.PublicKey
}

func (r staticResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	if domain == r.domain && kid == r.kid {
		return r.pub, nil
	}
	return nil, fmt.Errorf("no key for %s/%s", domain, kid)
}
func (r staticResolver) Refresh(string) error { return nil }

// fixedKey deterministically derives an ed25519 keypair from label, so
// re-running the generator produces byte-identical vectors every time.
func fixedKey(label string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("awp-sig-vector-seed:" + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, base64.RawURLEncoding.EncodeToString(seed[:])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// signedRequest builds and signs a request, returning it plus the fields a
// vector needs to record.
func signedRequest(priv ed25519.PrivateKey, domain, kid, method, url string, body []byte, extraHeaders map[string]string, created time.Time) (*http.Request, string, string, *string, string) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fatalf("new request: %v", err)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if err := httpsig.Sign(req, body, priv, domain+"/"+kid, created); err != nil {
		fatalf("sign: %v", err)
	}

	sigInput := req.Header.Get("Signature-Input")
	sig := req.Header.Get("Signature")
	var digest *string
	if d := req.Header.Get("Content-Digest"); d != "" {
		digest = &d
	}

	parsed, err := httpsig.ParseSignatureInput(sigInput)
	if err != nil {
		fatalf("re-parse own Signature-Input: %v", err)
	}
	base, err := httpsig.RequestSignatureBase(req, parsed.Params)
	if err != nil {
		fatalf("reconstruct signature base: %v", err)
	}
	return req, sigInput, sig, digest, base
}

// selfCheck re-verifies a (possibly tampered) request against this repo's
// own httpsig.Verify and asserts the outcome matches want, aborting the
// whole generation run on any mismatch — a vector that doesn't actually
// exercise what it claims to must never be written.
func selfCheck(name string, req *http.Request, body []byte, deps httpsig.Deps, now time.Time, want expectation) {
	result := httpsig.Verify(req, body, now, deps)
	gotStatus := result.Status
	gotCode := ""
	if result.Err != nil {
		gotCode = result.Err.Code
	}
	if gotStatus != want.Status || gotCode != want.Code {
		detail := ""
		if result.Err != nil {
			detail = result.Err.Detail
		}
		fatalf("self-check failed for %q: got status=%d code=%q (%s), want status=%d code=%q",
			name, gotStatus, gotCode, detail, want.Status, want.Code)
	}
}

// selfCheckResponse mirrors selfCheck for the response side (awp-sig §3):
// re-verifies resp against this repo's own httpsig.VerifyResponse and
// aborts generation on any mismatch from want. want.Status is unused here
// (VerifyResponse has no HTTP status of its own to compare); only
// want.Code matters, with "" meaning "expect no error."
func selfCheckResponse(name string, resp *http.Response, body []byte, resolver httpsig.KeyResolver, now time.Time, want expectation) {
	result := httpsig.VerifyResponse(resp, body, now, resolver)
	gotCode := ""
	if result.Err != nil {
		gotCode = result.Err.Code
	}
	if gotCode != want.Code {
		detail := ""
		if result.Err != nil {
			detail = result.Err.Detail
		}
		fatalf("self-check failed for %q: got code=%q (%s), want code=%q", name, gotCode, detail, want.Code)
	}
}

func writeResponseVector(dir string, v responseVector) {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("marshal %s: %v", v.Name, err)
	}
	path := filepath.Join(dir, v.Name+".json")
	if err := os.WriteFile(path, append(buf, '\n'), 0644); err != nil {
		fatalf("write %s: %v", path, err)
	}
	fmt.Println("wrote", path)
}

func writeVector(dir string, v vector) {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("marshal %s: %v", v.Name, err)
	}
	path := filepath.Join(dir, v.Name+".json")
	if err := os.WriteFile(path, append(buf, '\n'), 0644); err != nil {
		fatalf("write %s: %v", path, err)
	}
	fmt.Println("wrote", path)
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	genBodylessGET(dir)
	genPOSTWithBody(dir)
	genPOSTWithSession(dir)
	genPOSTWithDelegation(dir)
	genFailureStep1MissingSignatureInput(dir)
	genFailureStep1UnknownLabel(dir)
	genFailureStep1ForbiddenParam(dir)
	genFailureStep1MissingComponent(dir)
	genFailureStep2CreatedOutsideWindow(dir)
	genFailureStep3DigestMismatch(dir)
	genFailureStep4UnknownKey(dir)
	genFailureStep5BadSignature(dir)
	genFailureStep6DelegationInvalid(dir)
	genFailureStep7SessionInvalid(dir)
	genResponseSigned(dir)
	genResponseTamperedSignature(dir)
}

func genBodylessGET(dir string) {
	const name = "bodyless-get"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/generate-invoice"

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodGet, url, nil, nil, created)
	selfCheck(name, req, nil, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, expectation{Status: 0})

	writeVector(dir, vector{
		Name:        name,
		Description: "Bodyless GET: no Content-Digest, no body-related components.",
		Domain:      domain, Kid: kid,
		PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodGet, TargetURI: url,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest,
		SignatureBase: base, Expect: expectation{Status: 0},
	})
}

func genPOSTWithBody(dir string) {
	const name = "post-with-body"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/generate-invoice"
	body := []byte(`{"amount":42,"currency":"USD"}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, expectation{Status: 0})

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name:        name,
		Description: "POST with a body: Content-Digest is computed and covered.",
		Domain:      domain, Kid: kid,
		PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest,
		SignatureBase: base, Expect: expectation{Status: 0},
	})
}

func genPOSTWithSession(dir string) {
	const name = "post-with-session"
	pub, priv, seed := fixedKey(name)
	domain, kid := "caller.example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://provider.example.com/awp/tools/tool"
	body := []byte(`{}`)
	extra := map[string]string{"AWP-Session": "opaque-session-token-abc123"}

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, extra, created)
	deps := httpsig.Deps{
		ResolveKey:    staticResolver{domain, kid, pub},
		VerifySession: func(token, caller string) error { return nil }, // any token accepted for this fixture
	}
	selfCheck(name, req, body, deps, verifyAt, expectation{Status: 0})

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name:        name,
		Description: "POST with AWP-Session: the header is covered by the signature.",
		Domain:      domain, Kid: kid,
		PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		ExtraHeaders: extra,
		Created:      created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest,
		SignatureBase: base, Expect: expectation{Status: 0},
		Note: "A conforming verifier must resolve/accept the session token itself; this vector only proves AWP-Session is correctly covered by the signature.",
	})
}

func genPOSTWithDelegation(dir string) {
	const name = "post-with-delegation-2link"
	pub, priv, seed := fixedKey(name)
	domain, kid := "assistant.acme.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://provider.example.com/awp/tools/tool"
	body := []byte(`{}`)
	target := "provider.example.com#tool"

	_, rootPriv, _ := fixedKey(name + "-root")
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	rootDomain := "user-root.example.com"

	root := delegation.Link{
		Delegator: rootDomain,
		Delegate:  "assistant.acme.com#relay",
		Scope:     delegation.Scope{To: &target},
		Expires:   created.Add(time.Hour).Format(time.RFC3339),
		Nonce:     "01arz3ndektsv4rrffq69g5fav",
	}
	if err := root.Sign(rootPriv, "k1"); err != nil {
		fatalf("sign root delegation link: %v", err)
	}
	second := delegation.Link{
		Delegator: "assistant.acme.com#relay",
		Delegate:  domain,
		Scope:     delegation.Scope{},
		Expires:   created.Add(time.Hour).Format(time.RFC3339),
		Nonce:     "01arz3ndektsv4rrffq69g5fbv",
	}
	if err := second.Sign(priv, kid); err != nil {
		fatalf("sign second delegation link: %v", err)
	}
	chain := []delegation.Link{root, second}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		fatalf("marshal delegation chain: %v", err)
	}
	extra := map[string]string{"AWP-Delegation": base64.RawURLEncoding.EncodeToString(chainJSON)}

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, extra, created)

	multiResolver := multiKeyResolver{keys: map[string]ed25519.PublicKey{
		rootDomain + "/k1": rootPub,
		domain + "/" + kid: pub,
	}}
	deps := httpsig.Deps{ResolveKey: multiResolver, Target: target}
	selfCheck(name, req, body, deps, verifyAt, expectation{Status: 0})

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name:        name,
		Description: "POST with a 2-link AWP-Delegation chain, root scoped `to` the target entity.",
		Domain:      domain, Kid: kid,
		PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		ExtraHeaders: extra,
		Created:      created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest,
		SignatureBase:    base,
		TrustedKeys:      []trustedKey{{Domain: rootDomain, Kid: "k1", PubKey: b64(rootPub)}},
		DelegationTarget: target,
		Expect:           expectation{Status: 0},
	})
}

// multiKeyResolver backs the delegation vector, which needs two distinct
// signing domains resolvable at once (the request's own signer plus the
// delegation root's signer).
type multiKeyResolver struct{ keys map[string]ed25519.PublicKey }

func (r multiKeyResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}
func (r multiKeyResolver) Refresh(string) error { return nil }

func genFailureStep1MissingSignatureInput(dir string) {
	const name = "failure-step1-missing-signature-input"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	req.Header.Del("Signature-Input")
	want := expectation{Status: 400, Code: apperr.CodeMalformed}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "The Signature-Input header is entirely absent.",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: "", Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
		Note:   fmt.Sprintf("The correctly-signed Signature-Input for reference (removed for this vector) was: %s", sigInput),
	})
}

func genFailureStep1UnknownLabel(dir string) {
	const name = "failure-step1-unknown-label"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	tampered := "other=" + sigInput[len("awp="):]
	req.Header.Set("Signature-Input", tampered)
	want := expectation{Status: 400, Code: apperr.CodeMalformed}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "Signature-Input uses a label other than \"awp\".",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: tampered, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
	})
}

func genFailureStep1ForbiddenParam(dir string) {
	const name = "failure-step1-forbidden-param"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	tampered := sigInput + ";expires=1753089000"
	req.Header.Set("Signature-Input", tampered)
	want := expectation{Status: 400, Code: apperr.CodeMalformed}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "Signature-Input carries a forbidden `expires` parameter (awp-sig §1.2 MUST NOT appear).",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: tampered, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
	})
}

func genFailureStep1MissingComponent(dir string) {
	const name = "failure-step1-missing-component"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	tampered := fmt.Sprintf(`awp=("@method" "@target-uri");created=%d;keyid="%s/%s";alg="ed25519"`, created.Unix(), domain, kid)
	req.Header.Set("Signature-Input", tampered)
	want := expectation{Status: 400, Code: apperr.CodeMalformed}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "Signature-Input's declared component list drops \"content-digest\", which is present and required for a POST with a body.",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: tampered, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
		Note:   fmt.Sprintf("Correctly-signed Signature-Input for reference: %s", sigInput),
	})
}

func genFailureStep2CreatedOutsideWindow(dir string) {
	const name = "failure-step2-created-outside-window"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(time.Hour) // far outside the +-300s window
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	want := expectation{Status: 401, Code: apperr.CodeUnauthorized}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "verify_at is 1 hour after created, well outside the +-300s replay window.",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
	})
}

func genFailureStep3DigestMismatch(dir string) {
	const name = "failure-step3-digest-mismatch"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{"original":true}`)

	req, sigInput, sig, _, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	tamperedDigest := "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
	req.Header.Set("Content-Digest", tamperedDigest)
	want := expectation{Status: 400, Code: apperr.CodeMalformed}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "Content-Digest header is replaced after signing; must be rejected at step 3, before the signature is ever checked (step 5 would also fail, but must never be reached).",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: &tamperedDigest, SignatureBase: base,
		Expect: want,
	})
}

func genFailureStep4UnknownKey(dir string) {
	const name = "failure-step4-unknown-key"
	_, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	// Deliberately resolve against a DIFFERENT domain/kid than the request
	// actually used, simulating "this verifier has never heard of this key."
	want := expectation{Status: 401, Code: apperr.CodeUnauthorized}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{"different.example.com", "other-kid", nil}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "The verifier's key resolver has no entry for this request's (domain, kid).",
		Domain: domain, Kid: kid, PublicKey: "", PrivateKeySeed: seed,
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
		Note:   "public_key_b64url is intentionally omitted: a conforming verifier for this vector has no key material for " + domain + "/" + kid + " at all.",
	})
}

func genFailureStep5BadSignature(dir string) {
	const name = "failure-step5-bad-signature"
	pub, priv, seed := fixedKey(name)
	domain, kid := "example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://example.com/awp/tools/tool"
	body := []byte(`{}`)

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, nil, created)
	tamperedURL := "https://example.com/awp/tools/a-different-tool"
	req.URL.Path = "/awp/tools/a-different-tool"
	want := expectation{Status: 401, Code: apperr.CodeUnauthorized}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: staticResolver{domain, kid, pub}}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "@target-uri is changed after signing (same headers, same declared components) — the signature no longer verifies.",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: tamperedURL, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
		Note:   "signature_base above is what was ORIGINALLY signed (target_uri=" + url + "); target_uri in this vector is the tampered value the verifier actually sees.",
	})
}

func genFailureStep6DelegationInvalid(dir string) {
	const name = "failure-step6-delegation-invalid"
	pub, priv, seed := fixedKey(name)
	domain, kid := "assistant.acme.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://provider.example.com/awp/tools/tool"
	body := []byte(`{}`)
	target := "provider.example.com#tool"

	_, rootPriv, _ := fixedKey(name + "-root")
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	rootDomain := "user-root.example.com"

	root := delegation.Link{
		Delegator: rootDomain, Delegate: "assistant.acme.com#relay",
		Scope: delegation.Scope{To: &target}, Expires: created.Add(time.Hour).Format(time.RFC3339),
		Nonce: "01arz3ndektsv4rrffq69g5fav",
	}
	if err := root.Sign(rootPriv, "k1"); err != nil {
		fatalf("sign root link: %v", err)
	}
	second := delegation.Link{
		// Broken: final delegate does not match the request's own signing
		// domain, violating core §2.5 rule 4.
		Delegator: "assistant.acme.com#relay", Delegate: "someone-else.example.com",
		Scope: delegation.Scope{}, Expires: created.Add(time.Hour).Format(time.RFC3339),
		Nonce: "01arz3ndektsv4rrffq69g5fbv",
	}
	if err := second.Sign(priv, kid); err != nil {
		fatalf("sign second link: %v", err)
	}
	chain := []delegation.Link{root, second}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		fatalf("marshal chain: %v", err)
	}
	extra := map[string]string{"AWP-Delegation": base64.RawURLEncoding.EncodeToString(chainJSON)}

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, extra, created)
	multiResolver := multiKeyResolver{keys: map[string]ed25519.PublicKey{
		rootDomain + "/k1": rootPub,
		domain + "/" + kid: pub,
	}}
	want := expectation{Status: 403, Code: apperr.CodeUnauthorizedDelegation}
	selfCheck(name, req, body, httpsig.Deps{ResolveKey: multiResolver, Target: target}, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "AWP-Delegation's final delegate does not equal the request's signing principal (core §2.5 rule 4).",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		ExtraHeaders: extra,
		Created:      created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		TrustedKeys:      []trustedKey{{Domain: rootDomain, Kid: "k1", PubKey: b64(rootPub)}},
		DelegationTarget: target,
		Expect:           want,
	})
}

func genFailureStep7SessionInvalid(dir string) {
	const name = "failure-step7-session-invalid"
	pub, priv, seed := fixedKey(name)
	domain, kid := "caller.example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	url := "https://provider.example.com/awp/tools/tool"
	body := []byte(`{}`)
	extra := map[string]string{"AWP-Session": "some-token-the-provider-rejects"}

	req, sigInput, sig, digest, base := signedRequest(priv, domain, kid, http.MethodPost, url, body, extra, created)
	deps := httpsig.Deps{
		ResolveKey:    staticResolver{domain, kid, pub},
		VerifySession: func(token, caller string) error { return fmt.Errorf("session rejected for this fixture") },
	}
	want := expectation{Status: 401, Code: apperr.CodeUnauthorized}
	selfCheck(name, req, body, deps, verifyAt, want)

	bodyB64 := b64(body)
	writeVector(dir, vector{
		Name: name, Description: "AWP-Session is correctly signed/covered, but the token itself is invalid/expired/not-this-caller's per the provider's own session verification.",
		Domain: domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Method: http.MethodPost, TargetURI: url, BodyB64: &bodyB64,
		ExtraHeaders: extra,
		Created:      created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
	})
}

func genResponseSigned(dir string) {
	const name = "response-signed"
	pub, priv, seed := fixedKey(name)
	domain, kid := "provider.example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	body := []byte(`{"output":{"ok":true}}`)

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := httpsig.SignResponse(resp, body, priv, domain+"/"+kid, created); err != nil {
		fatalf("SignResponse: %v", err)
	}
	sigInput := resp.Header.Get("Signature-Input")
	sig := resp.Header.Get("Signature")
	var digest *string
	if d := resp.Header.Get("Content-Digest"); d != "" {
		digest = &d
	}
	parsed, err := httpsig.ParseSignatureInput(sigInput)
	if err != nil {
		fatalf("re-parse own Signature-Input: %v", err)
	}
	base, err := httpsig.ResponseSignatureBase(resp, parsed.Params)
	if err != nil {
		fatalf("reconstruct response signature base: %v", err)
	}
	selfCheckResponse(name, resp, body, staticResolver{domain, kid, pub}, verifyAt, expectation{Status: 0})

	bodyB64 := b64(body)
	writeResponseVector(dir, responseVector{
		Name:        name,
		Description: "A provider's successfully-signed sync response (awp-sig §3, SHOULD): @status and content-digest covered.",
		Domain:      domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Status: 200, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: sig, ContentDigest: digest, SignatureBase: base,
		Expect: expectation{Status: 0},
	})
}

func genResponseTamperedSignature(dir string) {
	const name = "response-tampered-signature"
	pub, priv, seed := fixedKey(name)
	domain, kid := "provider.example.com", "2026-07-01"
	created := time.Unix(1753088043, 0).UTC()
	verifyAt := created.Add(10 * time.Second)
	body := []byte(`{"output":{"ok":true}}`)

	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := httpsig.SignResponse(resp, body, priv, domain+"/"+kid, created); err != nil {
		fatalf("SignResponse: %v", err)
	}
	sigInput := resp.Header.Get("Signature-Input")
	var digest *string
	if d := resp.Header.Get("Content-Digest"); d != "" {
		digest = &d
	}
	parsed, err := httpsig.ParseSignatureInput(sigInput)
	if err != nil {
		fatalf("re-parse own Signature-Input: %v", err)
	}
	base, err := httpsig.ResponseSignatureBase(resp, parsed.Params)
	if err != nil {
		fatalf("reconstruct response signature base: %v", err)
	}

	// Corrupt the signature AFTER capturing what was genuinely signed
	// above — same convention as failure-step5-bad-signature: the vector
	// records the real signature_base, but a tampered signature value.
	sigB64, err := httpsig.ParseSignature(resp.Header.Get("Signature"))
	if err != nil {
		fatalf("parse own signature: %v", err)
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		fatalf("decode own signature: %v", err)
	}
	rawSig[0] ^= 0xFF
	tamperedSig := httpsig.Label + "=:" + base64.RawURLEncoding.EncodeToString(rawSig) + ":"
	resp.Header.Set("Signature", tamperedSig)

	want := expectation{Status: 401, Code: apperr.CodeUnauthorized}
	selfCheckResponse(name, resp, body, staticResolver{domain, kid, pub}, verifyAt, want)

	bodyB64 := b64(body)
	writeResponseVector(dir, responseVector{
		Name:        name,
		Description: "A sync response's Signature is present but does not verify — awp-sig §3: a present-but-invalid response signature MUST be treated as an error (an absent one would not be).",
		Domain:      domain, Kid: kid, PrivateKeySeed: seed, PublicKey: b64(pub),
		Status: 200, BodyB64: &bodyB64,
		Created: created.Unix(), VerifyAt: verifyAt.Format(time.RFC3339),
		SignatureInput: sigInput, Signature: tamperedSig, ContentDigest: digest, SignatureBase: base,
		Expect: want,
		Note:   "signature_base above is what was GENUINELY signed; signature in this vector is deliberately corrupted afterward.",
	})
}
