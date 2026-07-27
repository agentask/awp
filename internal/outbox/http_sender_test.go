package outbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
)

func TestParseRetryAfter_NumericSeconds(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d, ok := parseRetryAfter("120", now)
	if !ok || d != 120*time.Second {
		t.Fatalf("got (%v, %v), want (120s, true)", d, ok)
	}
}

func TestParseRetryAfter_HTTPDate_Future(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	future := now.Add(90 * time.Second)
	d, ok := parseRetryAfter(future.Format(http.TimeFormat), now)
	if !ok {
		t.Fatal("expected ok=true for a valid HTTP-date")
	}
	if d != 90*time.Second {
		t.Fatalf("got %v, want 90s", d)
	}
}

func TestParseRetryAfter_HTTPDate_PastClampsToZero(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	past := now.Add(-90 * time.Second)
	d, ok := parseRetryAfter(past.Format(http.TimeFormat), now)
	if !ok {
		t.Fatal("expected ok=true even for a past HTTP-date")
	}
	if d != 0 {
		t.Fatalf("got %v, want 0 (clamped, never negative)", d)
	}
}

func TestParseRetryAfter_Malformed_NotHonored(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	if _, ok := parseRetryAfter("not-a-valid-value", now); ok {
		t.Fatal("expected ok=false for a value that's neither delta-seconds nor an HTTP-date")
	}
}

func TestHTTPSender_Send_HonorsHTTPDateRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	retryAt := now.Add(45 * time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAt.Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	sender := &HTTPSender{
		Clock:    clock.NewFixed(now),
		InboxURL: func(string) (string, error) { return srv.URL, nil },
	}
	status, retryAfter, hasRetryAfter, err := sender.Send(context.Background(), "receiver.example", []byte(`{}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if !hasRetryAfter {
		t.Fatal("expected hasRetryAfter=true")
	}
	if retryAfter != 45*time.Second {
		t.Fatalf("retryAfter = %v, want 45s", retryAfter)
	}
}

func TestHTTPSender_Send_NumericRetryAfterStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	sender := &HTTPSender{InboxURL: func(string) (string, error) { return srv.URL, nil }}
	_, retryAfter, hasRetryAfter, err := sender.Send(context.Background(), "receiver.example", []byte(`{}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !hasRetryAfter || retryAfter != 30*time.Second {
		t.Fatalf("got (%v, %v), want (30s, true)", retryAfter, hasRetryAfter)
	}
}

func TestHTTPSender_NotifyWake_POSTsEmptyBodyToDeclaredEndpoint(t *testing.T) {
	var gotMethod string
	var gotBodyLen int
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		gotBodyLen = len(body)
		w.WriteHeader(http.StatusOK)
		close(done)
	}))
	defer srv.Close()

	sender := &HTTPSender{WakeURL: func(string) (string, bool, error) { return srv.URL, true, nil }}
	sender.NotifyWake(context.Background(), "receiver.example")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wake endpoint was never called")
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotBodyLen != 0 {
		t.Fatalf("body length = %d, want 0 (empty body)", gotBodyLen)
	}
}

func TestHTTPSender_NotifyWake_NoEndpointDeclared_NeverCalls(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := &HTTPSender{WakeURL: func(string) (string, bool, error) { return "", false, nil }}
	sender.NotifyWake(context.Background(), "receiver.example")
	if called {
		t.Fatal("expected no request when the domain declares no wake endpoint")
	}
}

func TestHTTPSender_NotifyWake_NilWakeURL_NeverPanics(t *testing.T) {
	sender := &HTTPSender{}
	sender.NotifyWake(context.Background(), "receiver.example") // must not panic
}

func TestHTTPSender_NotifyWake_UnreachableEndpoint_Ignored(t *testing.T) {
	sender := &HTTPSender{
		WakeURL:     func(string) (string, bool, error) { return "http://127.0.0.1:1", true, nil },
		WakeTimeout: 200 * time.Millisecond,
	}
	sender.NotifyWake(context.Background(), "receiver.example") // must not panic or block long
}

func TestHTTPSender_Send_MalformedRetryAfterNotHonored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "banana")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	sender := &HTTPSender{InboxURL: func(string) (string, error) { return srv.URL, nil }}
	_, _, hasRetryAfter, err := sender.Send(context.Background(), "receiver.example", []byte(`{}`))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if hasRetryAfter {
		t.Fatal("expected hasRetryAfter=false for a malformed header")
	}
}
