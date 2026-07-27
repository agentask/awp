package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentask/awp/internal/identity"
)

func TestCheckWakeEndpointReachable_NoWakeDeclared_Skips(t *testing.T) {
	idx := &identity.Index{Domain: "no-wake.example.com"}
	r := checkWakeEndpointReachable(context.Background(), Options{}, idx)
	if r.Status != Skip {
		t.Fatalf("status=%s detail=%s, want Skip", r.Status, r.Detail)
	}
}

func TestCheckWakeEndpointReachable_ReachableEndpoint_Passes(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	idx := &identity.Index{Domain: "wake-reachable.example.com", Wake: &identity.Wake{Endpoint: srv.URL}}
	r := checkWakeEndpointReachable(context.Background(), Options{}, idx)
	if r.Status != Pass {
		t.Fatalf("status=%s detail=%s, want Pass", r.Status, r.Detail)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
}

func TestCheckWakeEndpointReachable_UnreachableEndpoint_Fails(t *testing.T) {
	idx := &identity.Index{
		Domain: "wake-unreachable.example.com",
		Wake:   &identity.Wake{Endpoint: "http://127.0.0.1:1/awp/wake"},
	}
	r := checkWakeEndpointReachable(context.Background(), Options{}, idx)
	if r.Status != Fail {
		t.Fatalf("status=%s detail=%s, want Fail", r.Status, r.Detail)
	}
}
