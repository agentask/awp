package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/agentask/awp/internal/apperr"
)

// VerifyResponseResult is VerifyResponse's outcome. Err is nil on success
// OR when the response carried no signature at all (response signing is
// awp-sig §3 SHOULD, not MUST — absence is not itself a failure).
type VerifyResponseResult struct {
	Err               *apperr.Error
	ProviderPrincipal string
	Signed            bool
}

func rejectResponse(code, detail string) VerifyResponseResult {
	return VerifyResponseResult{Err: &apperr.Error{Code: code, Detail: detail, Retryable: false}}
}

// VerifyResponse checks a provider's response signature per awp-sig §3: if
// Signature-Input is absent, that's fine (SHOULD, not MUST) and Signed is
// false. If present, a present-but-invalid signature MUST be treated as an
// error — this mirrors Verify's step structure but only the components a
// response actually has (@status, content-digest iff body).
func VerifyResponse(resp *http.Response, body []byte, now time.Time, resolveKey KeyResolver) VerifyResponseResult {
	sigInputHeader := resp.Header.Get("Signature-Input")
	if sigInputHeader == "" {
		return VerifyResponseResult{}
	}
	parsed, err := ParseSignatureInput(sigInputHeader)
	if err != nil {
		return rejectResponse(apperr.CodeMalformed, err.Error())
	}
	if parsed.Params.Alg != "ed25519" {
		return rejectResponse(apperr.CodeMalformed, "alg must be \"ed25519\"")
	}
	hasBody := len(body) > 0
	wantComponents := []string{derivedStatus}
	if hasBody {
		wantComponents = append(wantComponents, componentDigest)
	}
	if !equalStringSlices(parsed.Params.Components, wantComponents) {
		return rejectResponse(apperr.CodeMalformed, "covered components do not match this response")
	}

	sigHeader := resp.Header.Get("Signature")
	if sigHeader == "" {
		return rejectResponse(apperr.CodeMalformed, "missing Signature")
	}
	sigB64, err := ParseSignature(sigHeader)
	if err != nil {
		return rejectResponse(apperr.CodeMalformed, err.Error())
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return rejectResponse(apperr.CodeMalformed, "bad Signature encoding")
	}

	createdAt := time.Unix(parsed.Params.Created, 0)
	if d := now.Sub(createdAt); d > createdWindow || d < -createdWindow {
		return rejectResponse(apperr.CodeUnauthorized, "created outside the ±300s window")
	}

	if hasBody {
		digestHeader := resp.Header.Get("Content-Digest")
		if digestHeader == "" {
			return rejectResponse(apperr.CodeMalformed, "missing Content-Digest for a response with a body")
		}
		if err := VerifyContentDigest(digestHeader, body); err != nil {
			return rejectResponse(apperr.CodeMalformed, err.Error())
		}
	}

	domain, kid, ok := strings.Cut(parsed.Params.KeyID, "/")
	if !ok {
		return rejectResponse(apperr.CodeMalformed, "keyid must be {domain}/{kid}")
	}
	pub, err := resolveKey.Resolve(domain, kid)
	if err != nil {
		_ = resolveKey.Refresh(domain)
		if pub, err = resolveKey.Resolve(domain, kid); err != nil {
			return rejectResponse(apperr.CodeUnauthorized, "unknown or revoked key: "+err.Error())
		}
	}

	base, err := signatureBase(parsed.Params.Components, func(c string) (string, bool) {
		return responseComponentValue(resp, c)
	}, parsed.RawValue)
	if err != nil {
		return rejectResponse(apperr.CodeMalformed, err.Error())
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		return rejectResponse(apperr.CodeUnauthorized, "signature verification failed")
	}

	return VerifyResponseResult{ProviderPrincipal: domain, Signed: true}
}
