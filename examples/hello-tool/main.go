// Command hello-tool is the smallest possible AWP demo: one domain hosts a
// stateless sync tool, and a caller invokes it using sdk/go — the same
// public client a third-party Go program would use to speak AWP without
// running its own daemon.
//
// Everything runs in a single process on an ephemeral local port, so this
// is `go run .` with no setup: no DNS, no real certificates, no other
// terminal. That locality is what's cut for convenience — swap the
// httptest.NewTLSServer below for a real listener + a real domain and
// nothing else about this program changes.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/store"
	awp "github.com/agentask/awp/sdk/go"
)

// staticResolver is the minimum a daemon needs to verify a caller's
// signature: a (domain, kid) -> public key lookup. A real deployment uses
// internal/keyresolver.HTTPResolver, which fetches and caches
// /.well-known/awp.json over real DNS+HTTPS instead of a map a test
// preloads — see docs/architecture.md.
type staticResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *staticResolver) trust(domain, kid string, pub ed25519.PublicKey) {
	r.keys[domain+"/"+kid] = pub
}

func (r *staticResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key known for %s/%s", domain, kid)
	}
	return pub, nil
}

func (r *staticResolver) Refresh(string) error                { return nil }
func (r *staticResolver) ResolveInbox(string) (string, error) { return "", nil }
func (r *staticResolver) ResolveTransport(string, string) (string, bool, error) {
	return "", false, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	// --- Provider side: a domain hosting one stateless "multiply" tool ---
	toolDomain := "calc.example"
	_, toolPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(os.TempDir(), "hello-tool-calc.db")
	defer os.Remove(dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	resolver := &staticResolver{keys: map[string]ed25519.PublicKey{}}
	d, err := daemon.New(daemon.Config{
		Domain: toolDomain, Kid: "k1", Priv: toolPriv,
		Store: st, Clock: clock.Real{}, Resolver: resolver,
	})
	if err != nil {
		return fmt.Errorf("construct daemon: %w", err)
	}

	// httptest.NewTLSServer terminates real TLS with an auto-generated
	// certificate — this is core §6's mandatory HTTPS floor, not a
	// simplification; only the certificate's trust chain (self-signed
	// instead of a real CA) is test-only.
	srv := httptest.NewTLSServer(d)
	defer srv.Close()
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		return fmt.Errorf("finalize index: %w", err)
	}

	multiply := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		var args struct{ A, B int }
		if err := json.Unmarshal(input, &args); err != nil {
			return nil, &apperr.Error{Code: apperr.CodeUnsupportedBody, Detail: "want {\"a\":int,\"b\":int}"}
		}
		out, err := json.Marshal(map[string]any{"product": args.A * args.B, "computed_for": caller})
		if err != nil {
			return nil, &apperr.Error{Code: apperr.CodeInternal, Detail: err.Error()}
		}
		return out, nil
	}
	toolManifest := &manifest.Manifest{
		Awp: "0.1", Name: toolDomain + "#multiply", Kind: "tool", Version: "1.0.0",
		Description:  "Multiplies two integers.",
		IO:           manifest.IOSchema{Input: json.RawMessage(`{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}}}`)},
		Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
		State:        "stateless",
		Auth:         manifest.Auth{Sig: "required"},
		Pricing:      json.RawMessage("null"),
	}
	if err := d.RegisterTool(srv.URL, daemon.Tool{Manifest: toolManifest, Handler: multiply}); err != nil {
		return fmt.Errorf("register tool: %w", err)
	}

	// --- Caller side: a third-party program speaking AWP via sdk/go ---
	callerDomain := "agent.example"
	_, callerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	callerPub := callerPriv.Public().(ed25519.PublicKey)
	// The provider must be able to verify the caller's signature. A real
	// deployment resolves this via the caller's own published index; here
	// we hand it over directly since this demo's "caller.example" domain
	// publishes nothing anywhere.
	resolver.trust(callerDomain, "ck1", callerPub)

	client := &awp.Client{
		Domain: callerDomain, Kid: "ck1", Priv: callerPriv,
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}, //nolint:gosec // local self-signed demo cert
		IndexURL: func(domain string) string {
			if domain == toolDomain {
				return srv.URL + "/.well-known/awp.json"
			}
			return "https://" + domain + "/.well-known/awp.json"
		},
	}

	input, err := json.Marshal(map[string]int{"a": 6, "b": 7})
	if err != nil {
		return err
	}
	output, session, err := client.CallTool(ctx, toolDomain+"#multiply", input, awp.CallOptions{})
	if err != nil {
		return fmt.Errorf("call tool: %w", err)
	}
	fmt.Printf("tool output: %s\n", output)
	if session != nil {
		fmt.Println("(unexpected: a stateless tool should not issue a session)")
	}
	return nil
}
