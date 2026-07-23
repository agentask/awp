package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/delegation"
)

// createdWindow is the fixed replay window (awp-sig §2 step 2 / §4:
// "created + fixed 300s window is one fewer knob to misconfigure").
const createdWindow = 300 * time.Second

// KeyResolver resolves (domain, kid) to a public key, with a Refresh
// primitive for the core §0.1 rotation-race retry. Same shape as
// internal/inbox.KeyResolver, declared locally so this package doesn't
// need to depend on internal/inbox for a two-method interface.
type KeyResolver interface {
	Resolve(domain, kid string) (ed25519.PublicKey, error)
	Refresh(domain string) error
}

// SessionVerifier checks an AWP-Session token against the caller principal
// derived from the request's signing key (core §1.3).
type SessionVerifier func(token, callerPrincipal string) error

// Deps bundles what Verify needs beyond the request/body themselves.
type Deps struct {
	ResolveKey KeyResolver
	// Target is this endpoint's own principal (the tool/entity being
	// called) — checked against a delegation chain's scope.To, exactly as
	// an envelope's `to` field would be (core §2.5).
	Target string
	// VerifySession is called when AWP-Session is present. A nil
	// VerifySession on an endpoint that receives an AWP-Session header is
	// itself a verification failure (an endpoint that doesn't accept
	// sessions has no business receiving one).
	VerifySession SessionVerifier
}

// VerifyResult is Verify's outcome: Status/Err mirror
// internal/inbox.GateResult's shape (0/nil means success).
type VerifyResult struct {
	Status          int
	Err             *apperr.Error
	CallerPrincipal string
	Delegation      []delegation.Link
	HasSession      bool
}

func reject(status int, code, detail string) VerifyResult {
	return VerifyResult{Status: status, Err: &apperr.Error{Code: code, Detail: detail, Retryable: false}}
}

// Verify runs the awp-sig §2 algorithm against req, given the exact bytes
// of its body (already read by the caller — this package never touches
// req.Body, matching internal/inbox.Gate's pattern of taking raw bytes).
// Each of the 7 steps short-circuits with the specific status/code the
// spec assigns it.
func Verify(req *http.Request, body []byte, now time.Time, deps Deps) VerifyResult {
	// Step 1: parse Signature-Input; validate components and params.
	sigInputHeader := req.Header.Get("Signature-Input")
	if sigInputHeader == "" {
		return reject(400, apperr.CodeMalformed, "missing Signature-Input")
	}
	parsed, err := ParseSignatureInput(sigInputHeader)
	if err != nil {
		return reject(400, apperr.CodeMalformed, err.Error())
	}
	if parsed.Params.Alg != "ed25519" {
		return reject(400, apperr.CodeMalformed, "alg must be \"ed25519\"")
	}
	hasBody := len(body) > 0
	wantComponents := CoveredComponents(hasBody, req.Header)
	if !equalStringSlices(parsed.Params.Components, wantComponents) {
		return reject(400, apperr.CodeMalformed, "covered components do not match this request")
	}

	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		return reject(400, apperr.CodeMalformed, "missing Signature")
	}
	sigB64, err := ParseSignature(sigHeader)
	if err != nil {
		return reject(400, apperr.CodeMalformed, err.Error())
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return reject(400, apperr.CodeMalformed, "bad Signature encoding")
	}

	// Step 2: created within ±300s.
	createdAt := time.Unix(parsed.Params.Created, 0)
	if d := now.Sub(createdAt); d > createdWindow || d < -createdWindow {
		return reject(401, apperr.CodeUnauthorized, "created outside the ±300s window")
	}

	// Step 3: digest before signature — never verify a signature over a
	// digest that hasn't itself been checked.
	if hasBody {
		digestHeader := req.Header.Get("Content-Digest")
		if digestHeader == "" {
			return reject(400, apperr.CodeMalformed, "missing Content-Digest for a request with a body")
		}
		if err := VerifyContentDigest(digestHeader, body); err != nil {
			return reject(400, apperr.CodeMalformed, err.Error())
		}
	}

	// Step 4: resolve keyid, one refresh on failure (core §0.1 rotation
	// race), then hard-fail.
	domain, kid, ok := strings.Cut(parsed.Params.KeyID, "/")
	if !ok {
		return reject(400, apperr.CodeMalformed, "keyid must be {domain}/{kid}")
	}
	pub, err := deps.ResolveKey.Resolve(domain, kid)
	if err != nil {
		_ = deps.ResolveKey.Refresh(domain)
		if pub, err = deps.ResolveKey.Resolve(domain, kid); err != nil {
			return reject(401, apperr.CodeUnauthorized, "unknown or revoked key: "+err.Error())
		}
	}

	// Step 5: reconstruct the signature base from the RECEIVED params
	// value (not a re-serialization) and verify.
	base, err := signatureBase(parsed.Params.Components, func(c string) (string, bool) {
		return requestComponentValue(req, c)
	}, parsed.RawValue)
	if err != nil {
		return reject(400, apperr.CodeMalformed, err.Error())
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		return reject(401, apperr.CodeUnauthorized, "signature verification failed")
	}

	callerPrincipal := domain
	result := VerifyResult{CallerPrincipal: callerPrincipal}

	// Step 6: delegation, if present. The final delegate must equal the
	// caller principal derived from keyid — for sync calls that's always a
	// bare domain, since keyid carries no entity fragment.
	if delHeader := req.Header.Get("AWP-Delegation"); delHeader != "" {
		chain, err := decodeDelegationChain(delHeader)
		if err != nil {
			return reject(403, apperr.CodeUnauthorizedDelegation, err.Error())
		}
		verifyIn := delegation.VerifyInput{
			Chain: chain, From: callerPrincipal, To: deps.Target,
			Now: now, ResolveKey: deps.ResolveKey.Resolve,
		}
		if err := delegation.Verify(verifyIn); err != nil {
			return reject(403, apperr.CodeUnauthorizedDelegation, err.Error())
		}
		result.Delegation = chain
	}

	// Step 7: session, if present.
	if sessHeader := req.Header.Get("AWP-Session"); sessHeader != "" {
		if deps.VerifySession == nil {
			return reject(401, apperr.CodeUnauthorized, "this endpoint does not accept sessions")
		}
		if err := deps.VerifySession(sessHeader, callerPrincipal); err != nil {
			return reject(401, apperr.CodeUnauthorized, "session invalid: "+err.Error())
		}
		result.HasSession = true
	}

	return result
}

func decodeDelegationChain(header string) ([]delegation.Link, error) {
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, errors.New("bad AWP-Delegation encoding")
	}
	var chain []delegation.Link
	if err := json.Unmarshal(raw, &chain); err != nil {
		return nil, errors.New("bad AWP-Delegation JSON")
	}
	return chain, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
