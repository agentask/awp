package keyresolver

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "keyresolver.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func signedIndex(t *testing.T, domain, kid string, pub ed25519.PublicKey, priv ed25519.PrivateKey, inbox string, revoked bool) []byte {
	t.Helper()
	idx := &identity.Index{
		Awp:     "0.1",
		Domain:  domain,
		Updated: "2026-07-21T09:00:00.000Z",
		Keys: []identity.Key{{
			Kid: kid, Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub),
			Created: "2026-07-01T00:00:00.000Z", Revoked: revoked,
		}},
		Inbox: inbox,
	}
	if err := idx.Sign(priv, kid); err != nil {
		t.Fatalf("sign index: %v", err)
	}
	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	return raw
}

// switchableIndexServer serves whatever []byte is currently set, so tests
// can simulate a domain updating its published index mid-run.
type switchableIndexServer struct {
	mu  sync.Mutex
	raw []byte
}

func newSwitchableIndexServer(initial []byte) (*switchableIndexServer, *httptest.Server) {
	s := &switchableIndexServer{raw: initial}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.raw)
	}))
	return s, srv
}

func (s *switchableIndexServer) set(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = raw
}

func TestResolve_FetchesAndCaches(t *testing.T) {
	pub, priv := mustKeypair(t)
	const domain = "example.com"
	raw := signedIndex(t, domain, "k1", pub, priv, "http://receiver/awp/inbox", false)
	_, srv := newSwitchableIndexServer(raw)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	got, err := r.Resolve(domain, "k1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("resolved key does not match the published key")
	}

	cached, found, err := st.GetKeysCache(domain)
	if err != nil || !found {
		t.Fatalf("GetKeysCache: %v, found=%v", err, found)
	}
	if string(cached) != string(raw) {
		t.Fatal("cached index bytes don't match what was fetched")
	}

	// Take the server down; a cached resolve must still succeed.
	srv.Close()
	got2, err := r.Resolve(domain, "k1")
	if err != nil {
		t.Fatalf("Resolve from cache after server down: %v", err)
	}
	if string(got2) != string(pub) {
		t.Fatal("cached resolve returned the wrong key")
	}
}

func TestRefresh_ForcesRefetch(t *testing.T) {
	pub1, priv1 := mustKeypair(t)
	pub2, priv2 := mustKeypair(t)
	const domain = "rotating.example.com"

	rawV1 := signedIndex(t, domain, "k1", pub1, priv1, "http://x/awp/inbox", false)
	switchable, srv := newSwitchableIndexServer(rawV1)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	if _, err := r.Resolve(domain, "k1"); err != nil {
		t.Fatalf("Resolve v1: %v", err)
	}

	// Domain rotates to a new key entirely and republishes.
	rawV2 := signedIndex(t, domain, "k2", pub2, priv2, "http://x/awp/inbox", false)
	switchable.set(rawV2)

	// Without Refresh, the stale cache still only knows k1.
	if _, err := r.Resolve(domain, "k2"); err == nil {
		t.Fatal("expected the stale cache to not know about k2 yet")
	}

	if err := r.Refresh(domain); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	got, err := r.Resolve(domain, "k2")
	if err != nil {
		t.Fatalf("Resolve v2 after refresh: %v", err)
	}
	if string(got) != string(pub2) {
		t.Fatal("resolved key does not match the rotated key")
	}
}

func TestResolve_RevokedKeyRejected(t *testing.T) {
	pub, priv := mustKeypair(t)
	const domain = "revoked.example.com"
	raw := signedIndex(t, domain, "k1", pub, priv, "http://x/awp/inbox", true)
	_, srv := newSwitchableIndexServer(raw)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	if _, err := r.Resolve(domain, "k1"); err == nil {
		t.Fatal("expected an error resolving a revoked key")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected a revocation-mentioning error, got: %v", err)
	}
}

func TestResolveInbox(t *testing.T) {
	pub, priv := mustKeypair(t)
	const domain = "inbox-test.example.com"
	raw := signedIndex(t, domain, "k1", pub, priv, "http://receiver.local/awp/inbox", false)
	_, srv := newSwitchableIndexServer(raw)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	got, err := r.ResolveInbox(domain)
	if err != nil {
		t.Fatalf("ResolveInbox: %v", err)
	}
	if got != "http://receiver.local/awp/inbox" {
		t.Fatalf("got %q, want the published inbox URL", got)
	}
}

func TestResolveTransport(t *testing.T) {
	pub, priv := mustKeypair(t)
	const domain = "quic-test.example.com"
	idx := &identity.Index{
		Awp: "0.1", Domain: domain, Updated: "2026-07-21T09:00:00.000Z",
		Keys: []identity.Key{{
			Kid: "k1", Alg: "ed25519", Pub: base64.RawURLEncoding.EncodeToString(pub),
			Created: "2026-07-01T00:00:00.000Z",
		}},
		Inbox:      "http://x/awp/inbox",
		Transports: []identity.Transport{{Proto: "awp/1", Endpoint: "quic-test.example.com:8443"}},
	}
	if err := idx.Sign(priv, "k1"); err != nil {
		t.Fatalf("sign index: %v", err)
	}
	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	_, srv := newSwitchableIndexServer(raw)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	endpoint, ok, err := r.ResolveTransport(domain, "awp/1")
	if err != nil {
		t.Fatalf("ResolveTransport: %v", err)
	}
	if !ok || endpoint != "quic-test.example.com:8443" {
		t.Fatalf("got endpoint=%q ok=%v, want quic-test.example.com:8443/true", endpoint, ok)
	}

	_, ok, err = r.ResolveTransport(domain, "some-other-proto")
	if err != nil {
		t.Fatalf("ResolveTransport (absent proto): %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an unadvertised proto, not an error")
	}
}

func TestLoad_RejectsBadSelfSignature(t *testing.T) {
	pub, priv := mustKeypair(t)
	const domain = "tampered.example.com"
	raw := signedIndex(t, domain, "k1", pub, priv, "http://x/awp/inbox", false)

	// Tamper with the served bytes after signing (flip the domain name).
	tampered := []byte(strings.Replace(string(raw), domain, "different.example.com", 1))
	_, srv := newSwitchableIndexServer(tampered)
	defer srv.Close()

	st := openTestStore(t)
	r := &HTTPResolver{Store: st, Clock: clock.NewFixed(time.Now()), BaseURL: func(string) string { return srv.URL }}

	if _, err := r.Resolve(domain, "k1"); err == nil {
		t.Fatal("expected a signature-verification error for a tampered index")
	}
}
