package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"
)

// Sign signs req per awp-sig §1: computes Content-Digest if body is
// non-empty, determines the exact covered-component list (awp-sig §1.1),
// and sets Signature-Input and Signature. Any AWP-* headers the caller
// wants covered (AWP-Session, AWP-Delegation) MUST already be set on
// req.Header before calling Sign — covered components are read from
// whatever's present, not supplied separately.
func Sign(req *http.Request, body []byte, priv ed25519.PrivateKey, keyID string, now time.Time) error {
	hasBody := len(body) > 0
	if hasBody {
		req.Header.Set("Content-Digest", ComputeContentDigest(body))
	}
	components := CoveredComponents(hasBody, req.Header)
	params := Params{Components: components, Created: now.Unix(), KeyID: keyID, Alg: "ed25519"}

	base, err := signatureBase(components, func(c string) (string, bool) {
		return requestComponentValue(req, c)
	}, params.serializeValue())
	if err != nil {
		return err
	}

	sig := ed25519.Sign(priv, []byte(base))
	req.Header.Set("Signature-Input", params.HeaderValue())
	req.Header.Set("Signature", Label+"=:"+base64.RawURLEncoding.EncodeToString(sig)+":")
	return nil
}

// SignResponse signs resp per awp-sig §3: covered components @status and
// content-digest (iff body non-empty), keyid from the provider's own
// domain. resp.StatusCode must already be set.
func SignResponse(resp *http.Response, body []byte, priv ed25519.PrivateKey, keyID string, now time.Time) error {
	hasBody := len(body) > 0
	if hasBody {
		resp.Header.Set("Content-Digest", ComputeContentDigest(body))
	}
	components := []string{derivedStatus}
	if hasBody {
		components = append(components, componentDigest)
	}
	params := Params{Components: components, Created: now.Unix(), KeyID: keyID, Alg: "ed25519"}

	base, err := signatureBase(components, func(c string) (string, bool) {
		return responseComponentValue(resp, c)
	}, params.serializeValue())
	if err != nil {
		return err
	}

	sig := ed25519.Sign(priv, []byte(base))
	resp.Header.Set("Signature-Input", params.HeaderValue())
	resp.Header.Set("Signature", Label+"=:"+base64.RawURLEncoding.EncodeToString(sig)+":")
	return nil
}
