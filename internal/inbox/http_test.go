package inbox

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
)

func TestServeHTTP_ValidEnvelope_202(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeypair(t)
	r := newFakeResolver()
	r.add(testDomain, testKid, pub)
	g := newTestGate(t, r, clock.NewFixed(now))

	_, raw := signedEnvelope(t, priv, now, 3600)
	req := httptest.NewRequest(http.MethodPost, "/awp/inbox", strings.NewReader(string(raw)))
	rec := httptest.NewRecorder()

	g.ServeHTTP(rec, req)

	if rec.Code != 202 {
		t.Fatalf("status = %d, want 202; body: %s", rec.Code, rec.Body.String())
	}
}

func TestServeHTTP_MalformedBody_400WithErrorBody(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	r := newFakeResolver()
	g := newTestGate(t, r, clock.NewFixed(now))

	req := httptest.NewRequest(http.MethodPost, "/awp/inbox", strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()

	g.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body apperr.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not the shared error grammar: %v (%s)", err, rec.Body.String())
	}
	if body.Error == nil || body.Error.Code != apperr.CodeMalformed {
		t.Fatalf("expected code %q, got %+v", apperr.CodeMalformed, body.Error)
	}
}

func TestServeHTTP_RejectsNonPost(t *testing.T) {
	r := newFakeResolver()
	g := newTestGate(t, r, clock.NewFixed(time.Now()))

	req := httptest.NewRequest(http.MethodGet, "/awp/inbox", nil)
	rec := httptest.NewRecorder()

	g.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
