package httpsig

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Label is the only signature label this subset recognizes (awp-sig §1:
// "Exactly one signature per message, label `awp`").
const Label = "awp"

// Params is the parsed signature parameters (awp-sig §1.2): created, keyid,
// alg, plus the ordered list of covered component identifiers.
type Params struct {
	Components []string
	Created    int64
	KeyID      string
	Alg        string
}

// serializeValue renders the params WITHOUT the "awp=" label — this is
// exactly the value RFC 9421 §2.5 wants for the signature base's
// "@signature-params" line.
func (p Params) serializeValue() string {
	var sb strings.Builder
	sb.WriteByte('(')
	for i, c := range p.Components {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte('"')
		sb.WriteString(c)
		sb.WriteByte('"')
	}
	sb.WriteByte(')')
	fmt.Fprintf(&sb, ";created=%d;keyid=%q;alg=%q", p.Created, p.KeyID, p.Alg)
	return sb.String()
}

// HeaderValue renders the full Signature-Input header value, e.g.
// `awp=("@method" "@target-uri");created=...;keyid="...";alg="ed25519"`.
func (p Params) HeaderValue() string {
	return Label + "=" + p.serializeValue()
}

var (
	// ErrMalformedSignatureInput covers anything not matching this
	// subset's exact grammar: unknown label, missing components, missing
	// required params, unparseable syntax.
	ErrMalformedSignatureInput = errors.New("httpsig: malformed Signature-Input")
	// ErrForbiddenParam means expires, nonce, or tag was present (awp-sig
	// §1.2: "MUST NOT appear").
	ErrForbiddenParam = errors.New("httpsig: forbidden signature parameter present")
)

var (
	labelRe    = regexp.MustCompile(`^awp=(\(.*)$`)
	compListRe = regexp.MustCompile(`^\(((?:"[^"]*"(?: "[^"]*")*)?)\)((?:;[a-zA-Z]+=(?:"[^"]*"|-?[0-9]+))*)$`)
)

// ParsedSignatureInput holds both the structured Params and the exact raw
// value substring (everything after "awp="), which MUST be reused verbatim
// when reconstructing the signature base for verification — re-serializing
// would silently accept a signature over bytes the signer never actually
// signed if their serialization style (whitespace, param order) differed
// from ours.
type ParsedSignatureInput struct {
	Params   Params
	RawValue string
}

// ParseSignatureInput parses a Signature-Input header value, accepting
// only the exact awp-sig §1 grammar: label "awp", REQUIRED created/keyid/
// alg, and no other params. Anything else — an unknown label, a missing or
// extra component, a forbidden param, or bytes that don't parse at all —
// is rejected per this subset's "no negotiation, no algorithm agility"
// design (awp-sig header note).
func ParseSignatureInput(header string) (ParsedSignatureInput, error) {
	m := labelRe.FindStringSubmatch(header)
	if m == nil {
		return ParsedSignatureInput{}, fmt.Errorf("%w: unknown label or bad syntax", ErrMalformedSignatureInput)
	}
	rawValue := m[1]

	cm := compListRe.FindStringSubmatch(rawValue)
	if cm == nil {
		return ParsedSignatureInput{}, fmt.Errorf("%w: bad component-list or param syntax", ErrMalformedSignatureInput)
	}
	componentsPart, paramsPart := cm[1], cm[2]

	var components []string
	if componentsPart != "" {
		for tok := range strings.SplitSeq(componentsPart, " ") {
			components = append(components, strings.Trim(tok, `"`))
		}
	}

	params := Params{Components: components}
	seen := map[string]bool{}
	for kv := range strings.SplitSeq(paramsPart, ";") {
		if kv == "" {
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return ParsedSignatureInput{}, fmt.Errorf("%w: bad param %q", ErrMalformedSignatureInput, kv)
		}
		seen[key] = true
		switch key {
		case "created":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return ParsedSignatureInput{}, fmt.Errorf("%w: bad created value: %v", ErrMalformedSignatureInput, err)
			}
			params.Created = n
		case "keyid":
			params.KeyID = strings.Trim(val, `"`)
		case "alg":
			params.Alg = strings.Trim(val, `"`)
		case "expires", "nonce", "tag":
			return ParsedSignatureInput{}, fmt.Errorf("%w: %q", ErrForbiddenParam, key)
		default:
			return ParsedSignatureInput{}, fmt.Errorf("%w: unknown param %q", ErrMalformedSignatureInput, key)
		}
	}
	if !seen["created"] || !seen["keyid"] || !seen["alg"] {
		return ParsedSignatureInput{}, fmt.Errorf("%w: missing a required param (created/keyid/alg)", ErrMalformedSignatureInput)
	}

	return ParsedSignatureInput{Params: params, RawValue: rawValue}, nil
}

// ParseSignature extracts the raw signature bytes-as-base64url from a
// Signature header value of the form `awp=:BASE64URL:`.
func ParseSignature(header string) (string, error) {
	m := signatureRe.FindStringSubmatch(header)
	if m == nil {
		return "", fmt.Errorf("%w: bad Signature header syntax", ErrMalformedSignatureInput)
	}
	return m[1], nil
}

var signatureRe = regexp.MustCompile(`^awp=:([A-Za-z0-9_-]+):$`)
