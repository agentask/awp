package httpsig

import (
	"net/http"
	"testing"
	"time"
)

func TestVerifyResponse_AbsentSignatureIsNotAFailure(t *testing.T) {
	resolver := newFakeResolver()
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	result := VerifyResponse(resp, nil, time.Unix(1000, 0), resolver)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Signed {
		t.Fatal("Signed should be false when no Signature-Input was present")
	}
}

func TestSignVerifyResponse_RoundTrip_WithBody(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("provider.example", "k1", pub)

	body := []byte(`{"ok":true}`)
	now := time.Unix(2_000_000, 0)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := SignResponse(resp, body, priv, "provider.example/k1", now); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	result := VerifyResponse(resp, body, now, resolver)
	if result.Err != nil {
		t.Fatalf("VerifyResponse: %v", result.Err)
	}
	if !result.Signed {
		t.Fatal("expected Signed=true")
	}
	if result.ProviderPrincipal != "provider.example" {
		t.Fatalf("ProviderPrincipal = %q, want provider.example", result.ProviderPrincipal)
	}
}

func TestSignVerifyResponse_RoundTrip_Bodyless(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("provider.example", "k1", pub)

	now := time.Unix(2_000_000, 0)
	resp := &http.Response{StatusCode: 204, Header: http.Header{}}
	if err := SignResponse(resp, nil, priv, "provider.example/k1", now); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	result := VerifyResponse(resp, nil, now, resolver)
	if result.Err != nil {
		t.Fatalf("VerifyResponse: %v", result.Err)
	}
}

func TestVerifyResponse_TamperedBodyFailsDigest(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("provider.example", "k1", pub)

	now := time.Unix(2_000_000, 0)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := SignResponse(resp, []byte(`{"ok":true}`), priv, "provider.example/k1", now); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	result := VerifyResponse(resp, []byte(`{"ok":false}`), now, resolver)
	if result.Err == nil {
		t.Fatal("expected an error for tampered body")
	}
	if result.Err.Code != "malformed" {
		t.Fatalf("Code = %q, want malformed", result.Err.Code)
	}
}

func TestVerifyResponse_TamperedStatusFailsSignature(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	resolver.add("provider.example", "k1", pub)

	now := time.Unix(2_000_000, 0)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := SignResponse(resp, nil, priv, "provider.example/k1", now); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	resp.StatusCode = 500

	result := VerifyResponse(resp, nil, now, resolver)
	if result.Err == nil {
		t.Fatal("expected an error for tampered status")
	}
	if result.Err.Code != "unauthorized" {
		t.Fatalf("Code = %q, want unauthorized", result.Err.Code)
	}
}

func TestVerifyResponse_UnknownKeyRefreshesOnceThenFails(t *testing.T) {
	pub, priv := mustKeypair(t)
	resolver := newFakeResolver()
	_ = pub

	now := time.Unix(2_000_000, 0)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if err := SignResponse(resp, nil, priv, "provider.example/k1", now); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	result := VerifyResponse(resp, nil, now, resolver)
	if result.Err == nil {
		t.Fatal("expected an error for unknown key")
	}
	if len(resolver.refreshed) != 1 || resolver.refreshed[0] != "provider.example" {
		t.Fatalf("refreshed = %v, want one call for provider.example", resolver.refreshed)
	}
}
