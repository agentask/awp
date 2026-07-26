// Command stateful-tool-delegation demonstrates two core §1.3/§2.5
// features that hello-tool skips for simplicity:
//
//  1. Session lifecycle for a `state: provider` tool — the first call from
//     a caller gets a fresh session token back; a call that presents that
//     token doesn't get a new one.
//  2. Delegation — a delegate calls the tool while presenting a signed
//     proof that it's acting on a delegator's behalf, and the tool
//     attributes the call to the delegator, not the delegate.
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
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/store"
	awp "github.com/agentask/awp/sdk/go"
)

// staticResolver preloads (domain, kid) -> public key. See hello-tool's
// README for why a real deployment uses internal/keyresolver.HTTPResolver
// instead.
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

	// --- Provider: a stateful "counter" tool ---
	toolDomain := "notes.example"
	_, toolPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(os.TempDir(), "stateful-tool-notes.db")
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
	srv := httptest.NewTLSServer(d)
	defer srv.Close()
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		return fmt.Errorf("finalize index: %w", err)
	}

	// Attribute each call to whoever is ultimately responsible for it: the
	// delegation chain's root delegator when one is presented, otherwise
	// the caller itself. Keyed by that principal, not by session — this is
	// what a provider tracking usage/billing per *responsible party*
	// (rather than per signing key) looks like.
	counts := map[string]int{}
	counter := func(ctx context.Context, caller string, chain []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
		billTo := caller
		if len(chain) > 0 {
			billTo = chain[0].Delegator
		}
		counts[billTo]++
		out, err := json.Marshal(map[string]any{"caller": caller, "billed_to": billTo, "count": counts[billTo]})
		if err != nil {
			return nil, &apperr.Error{Code: apperr.CodeInternal, Detail: err.Error()}
		}
		return out, nil
	}
	toolManifest := &manifest.Manifest{
		Awp: "0.1", Name: toolDomain + "#counter", Kind: "tool", Version: "1.0.0",
		Description:  "Increments and returns a per-responsible-party call counter.",
		Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
		State:        "provider", // core §1.3: this state issues session tokens.
		Auth:         manifest.Auth{Sig: "required"},
		Pricing:      json.RawMessage("null"),
	}
	if err := d.RegisterTool(srv.URL, daemon.Tool{Manifest: toolManifest, Handler: counter}); err != nil {
		return fmt.Errorf("register tool: %w", err)
	}

	indexURL := func(domain string) string {
		if domain == toolDomain {
			return srv.URL + "/.well-known/awp.json"
		}
		return "https://" + domain + "/.well-known/awp.json"
	}
	insecureHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local self-signed demo cert

	// --- employee.example: calls the tool directly, twice ---
	employeeDomain := "employee.example"
	_, employeePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	resolver.trust(employeeDomain, "ek1", employeePriv.Public().(ed25519.PublicKey))
	employee := &awp.Client{Domain: employeeDomain, Kid: "ek1", Priv: employeePriv, HTTP: insecureHTTP, IndexURL: indexURL}

	input := json.RawMessage(`{}`)
	out1, session, err := employee.CallTool(ctx, toolDomain+"#counter", input, awp.CallOptions{})
	if err != nil {
		return fmt.Errorf("employee first call: %w", err)
	}
	fmt.Printf("1st call (no session yet):  %s\n", out1)
	if session == nil {
		return fmt.Errorf("expected a session from a provider tool's first call")
	}
	fmt.Printf("   -> issued session %s (expires %s)\n", session.Sid, session.Expires)

	out2, session2, err := employee.CallTool(ctx, toolDomain+"#counter", input, awp.CallOptions{Session: session.Token})
	if err != nil {
		return fmt.Errorf("employee second call: %w", err)
	}
	fmt.Printf("2nd call (reusing session): %s\n", out2)
	if session2 != nil {
		return fmt.Errorf("expected no re-issued session on an authenticated repeat call")
	}

	// --- acme.example delegates to employee.example, scoped to this tool ---
	acmeDomain := "acme.example"
	_, acmePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	resolver.trust(acmeDomain, "ak1", acmePriv.Public().(ed25519.PublicKey))
	acme := &awp.Client{Domain: acmeDomain, Kid: "ak1", Priv: acmePriv}

	scopedTo := toolDomain + "#counter"
	link, err := acme.SignDelegationLink(employeeDomain, delegation.Scope{To: &scopedTo}, time.Now().Add(time.Hour), envelope.NewID())
	if err != nil {
		return fmt.Errorf("sign delegation link: %w", err)
	}

	out3, _, err := employee.CallTool(ctx, toolDomain+"#counter", input, awp.CallOptions{Delegation: []delegation.Link{link}})
	if err != nil {
		return fmt.Errorf("delegated call: %w", err)
	}
	fmt.Printf("3rd call (on acme's behalf): %s\n", out3)
	fmt.Println("\nnote: employee.example signed all three calls, but the third is billed to acme.example — that's what the delegation chain proves.")
	return nil
}
