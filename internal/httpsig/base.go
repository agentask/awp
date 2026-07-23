package httpsig

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// derivedMethod and derivedTargetURI are the only "@"-prefixed derived
// components this subset uses (awp-sig §1.1: exactly @method and
// @target-uri, never anything else).
const (
	derivedMethod    = "@method"
	derivedTargetURI = "@target-uri"
	derivedStatus    = "@status"
	componentDigest  = "content-digest"
)

// CoveredComponents returns the exact, ordered covered-component list for
// a request (awp-sig §1.1): @method, @target-uri, content-digest (iff
// hasBody), then every AWP-* header present, lowercase, alphabetical.
func CoveredComponents(hasBody bool, header http.Header) []string {
	components := []string{derivedMethod, derivedTargetURI}
	if hasBody {
		components = append(components, componentDigest)
	}
	var awpHeaders []string
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "awp-") {
			awpHeaders = append(awpHeaders, lower)
		}
	}
	sort.Strings(awpHeaders)
	return append(components, awpHeaders...)
}

// signatureBase builds the RFC 9421 §2.5 signature base: one line per
// covered component ("name": value\n), terminated by the
// "@signature-params" line WITHOUT a trailing newline. rawParamsValue is
// the exact (unre-serialized) params value — see ParsedSignatureInput's
// doc comment for why that matters on the verify side.
func signatureBase(components []string, value func(component string) (string, bool), rawParamsValue string) (string, error) {
	var sb strings.Builder
	for _, c := range components {
		v, ok := value(c)
		if !ok {
			return "", fmt.Errorf("httpsig: missing value for covered component %q", c)
		}
		fmt.Fprintf(&sb, "%q: %s\n", c, v)
	}
	fmt.Fprintf(&sb, "%q: %s", "@signature-params", rawParamsValue)
	return sb.String(), nil
}

// RequestSignatureBase reconstructs the signature base for req given
// params, without performing any signing/verification. Exported for
// tooling that needs to inspect what would be (or was) signed — e.g.
// generating testdata/awp-sig/ conformance vectors — without duplicating
// this package's internal base-construction logic.
func RequestSignatureBase(req *http.Request, params Params) (string, error) {
	return signatureBase(params.Components, func(c string) (string, bool) {
		return requestComponentValue(req, c)
	}, params.serializeValue())
}

// requestComponentValue resolves a covered component's value from a
// request: derived components (@method, @target-uri) or a header field.
func requestComponentValue(req *http.Request, component string) (string, bool) {
	switch component {
	case derivedMethod:
		return req.Method, true
	case derivedTargetURI:
		return req.URL.String(), true
	default:
		v := req.Header.Get(component)
		if v == "" {
			return "", false
		}
		return v, true
	}
}

// responseComponentValue resolves a covered component's value from a
// response: @status or a header field.
func responseComponentValue(resp *http.Response, component string) (string, bool) {
	switch component {
	case derivedStatus:
		return fmt.Sprintf("%d", resp.StatusCode), true
	default:
		v := resp.Header.Get(component)
		if v == "" {
			return "", false
		}
		return v, true
	}
}
