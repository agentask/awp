package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// vectorFile mirrors testdata/awp-sig/generate.go's vector struct — kept
// as a separate, independent type (not shared code) so this test actually
// re-parses the JSON on disk the way a third-party implementation would,
// rather than trusting the generator's in-memory representation.
type vectorFile struct {
	Domain           string             `json:"domain"`
	Kid              string             `json:"kid"`
	PublicKeyB64     string             `json:"public_key_b64url"`
	Method           string             `json:"method"`
	TargetURI        string             `json:"target_uri"`
	BodyB64          *string            `json:"body_b64url"`
	ExtraHeaders     map[string]string  `json:"extra_headers,omitempty"`
	VerifyAt         string             `json:"verify_at"`
	SignatureInput   string             `json:"signature_input"`
	Signature        string             `json:"signature"`
	ContentDigest    *string            `json:"content_digest,omitempty"`
	TrustedKeys      []vectorTrustedKey `json:"trusted_keys,omitempty"`
	DelegationTarget string             `json:"delegation_target,omitempty"`
	Expect           struct {
		Status int    `json:"status"`
		Code   string `json:"code,omitempty"`
	} `json:"expect"`
}

type vectorTrustedKey struct {
	Domain string `json:"domain"`
	Kid    string `json:"kid"`
	PubKey string `json:"pub_b64url"`
}

// responseVectorFile mirrors generate.go's responseVector — the response
// counterpart to vectorFile, for the same "re-parse independently" reason.
// Response vectors have no "method" key at all, which is exactly how
// TestConformanceVectors tells the two shapes apart.
type responseVectorFile struct {
	Domain         string  `json:"domain"`
	Kid            string  `json:"kid"`
	PublicKeyB64   string  `json:"public_key_b64url"`
	Status         int     `json:"status"`
	BodyB64        *string `json:"body_b64url"`
	VerifyAt       string  `json:"verify_at"`
	SignatureInput string  `json:"signature_input"`
	Signature      string  `json:"signature"`
	ContentDigest  *string `json:"content_digest,omitempty"`
	Expect         struct {
		Status int    `json:"status"`
		Code   string `json:"code,omitempty"`
	} `json:"expect"`
}

// vectorKeyResolver resolves the request's own signer plus any additional
// TrustedKeys a vector declares (e.g. a delegation chain's root signer).
type vectorKeyResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r vectorKeyResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}
func (r vectorKeyResolver) Refresh(string) error { return nil }

// TestConformanceVectors replays every testdata/awp-sig/*.json fixture
// through this package's Verify, exactly as a third-party implementation
// would: parse the vector, reconstruct the HTTP request, verify, and check
// the outcome against the recorded expectation. This is what keeps the
// vectors load-bearing — a regression in Verify/Sign fails this test, not
// just the generator's own self-check (which only runs on demand).
func TestConformanceVectors(t *testing.T) {
	dir := "../../testdata/awp-sig"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var found int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		found++
		t.Run(e.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			// Request vectors always carry a "method"; response vectors
			// (awp-sig §3) never do — that absence is the discriminator.
			var probe struct {
				Method string `json:"method"`
			}
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if probe.Method == "" {
				var v responseVectorFile
				if err := json.Unmarshal(raw, &v); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				runResponseVector(t, v)
				return
			}
			var v vectorFile
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			runVector(t, v)
		})
	}
	if found == 0 {
		t.Fatal("no conformance vectors found — did generate.go run?")
	}
}

func runVector(t *testing.T, v vectorFile) {
	t.Helper()

	var body []byte
	if v.BodyB64 != nil {
		b, err := base64.RawURLEncoding.DecodeString(*v.BodyB64)
		if err != nil {
			t.Fatalf("decode body: %v", err)
		}
		body = b
	}

	req, err := http.NewRequest(v.Method, v.TargetURI, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, hv := range v.ExtraHeaders {
		req.Header.Set(k, hv)
	}
	if v.SignatureInput != "" {
		req.Header.Set("Signature-Input", v.SignatureInput)
	}
	if v.Signature != "" {
		req.Header.Set("Signature", v.Signature)
	}
	if v.ContentDigest != nil {
		req.Header.Set("Content-Digest", *v.ContentDigest)
	}

	verifyAt, err := time.Parse(time.RFC3339, v.VerifyAt)
	if err != nil {
		t.Fatalf("parse verify_at: %v", err)
	}

	keys := map[string]ed25519.PublicKey{}
	if v.PublicKeyB64 != "" {
		p, err := base64.RawURLEncoding.DecodeString(v.PublicKeyB64)
		if err != nil {
			t.Fatalf("decode public key: %v", err)
		}
		keys[v.Domain+"/"+v.Kid] = ed25519.PublicKey(p)
	}
	for _, tk := range v.TrustedKeys {
		p, err := base64.RawURLEncoding.DecodeString(tk.PubKey)
		if err != nil {
			t.Fatalf("decode trusted key %s/%s: %v", tk.Domain, tk.Kid, err)
		}
		keys[tk.Domain+"/"+tk.Kid] = ed25519.PublicKey(p)
	}

	deps := Deps{ResolveKey: vectorKeyResolver{keys: keys}, Target: v.DelegationTarget}
	if v.ExtraHeaders["AWP-Session"] != "" {
		if v.Expect.Status == 0 {
			deps.VerifySession = func(token, caller string) error { return nil }
		} else {
			deps.VerifySession = func(token, caller string) error { return fmt.Errorf("rejected per vector") }
		}
	}

	result := Verify(req, body, verifyAt, deps)
	if result.Status != v.Expect.Status {
		detail := ""
		if result.Err != nil {
			detail = result.Err.Detail
		}
		t.Fatalf("status = %d, want %d (detail: %s)", result.Status, v.Expect.Status, detail)
	}
	if v.Expect.Code != "" {
		if result.Err == nil || result.Err.Code != v.Expect.Code {
			t.Fatalf("code = %v, want %q", result.Err, v.Expect.Code)
		}
	}
}

// runResponseVector is runVector's counterpart for awp-sig §3 response
// vectors, replaying them through VerifyResponse instead of Verify.
func runResponseVector(t *testing.T, v responseVectorFile) {
	t.Helper()

	var body []byte
	if v.BodyB64 != nil {
		b, err := base64.RawURLEncoding.DecodeString(*v.BodyB64)
		if err != nil {
			t.Fatalf("decode body: %v", err)
		}
		body = b
	}

	resp := &http.Response{StatusCode: v.Status, Header: http.Header{}}
	if v.SignatureInput != "" {
		resp.Header.Set("Signature-Input", v.SignatureInput)
	}
	if v.Signature != "" {
		resp.Header.Set("Signature", v.Signature)
	}
	if v.ContentDigest != nil {
		resp.Header.Set("Content-Digest", *v.ContentDigest)
	}

	verifyAt, err := time.Parse(time.RFC3339, v.VerifyAt)
	if err != nil {
		t.Fatalf("parse verify_at: %v", err)
	}

	keys := map[string]ed25519.PublicKey{}
	if v.PublicKeyB64 != "" {
		p, err := base64.RawURLEncoding.DecodeString(v.PublicKeyB64)
		if err != nil {
			t.Fatalf("decode public key: %v", err)
		}
		keys[v.Domain+"/"+v.Kid] = ed25519.PublicKey(p)
	}

	result := VerifyResponse(resp, body, verifyAt, vectorKeyResolver{keys: keys})
	gotCode := ""
	if result.Err != nil {
		gotCode = result.Err.Code
	}
	if gotCode != v.Expect.Code {
		detail := ""
		if result.Err != nil {
			detail = result.Err.Detail
		}
		t.Fatalf("code = %q (%s), want %q", gotCode, detail, v.Expect.Code)
	}
}
