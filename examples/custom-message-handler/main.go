// Command custom-message-handler shows the one thing
// `examples/agent-messaging` deliberately leaves out: a real message
// handler. `internal/daemon.Config.MessageHandler` replaces the
// reference default (ack, then a fixed "received") with your own logic —
// this is what turns a daemon that only demonstrates the wire format
// into something that could plausibly be an agent.
//
// planner.example receives a `task` envelope and computes an answer
// instead of acking-then-echoing; user.example just sends it and prints
// whatever comes back.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// httpResolver is the same minimal real-HTTP resolver
// examples/agent-messaging uses — see its README for why this is a
// legitimate stand-in for internal/keyresolver.HTTPResolver in a demo
// with no DNS.
type httpResolver struct {
	http     *http.Client
	baseURLs map[string]string
}

func (r *httpResolver) fetchIndex(domain string) (*identity.Index, error) {
	base, ok := r.baseURLs[domain]
	if !ok {
		base = "https://" + domain
	}
	resp, err := r.http.Get(base + "/.well-known/awp.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var idx identity.Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	if err := idx.VerifySelfSig(); err != nil {
		return nil, fmt.Errorf("%s index signature invalid: %w", domain, err)
	}
	return &idx, nil
}

func (r *httpResolver) Resolve(domain, kid string) (ed25519.PublicKey, error) {
	idx, err := r.fetchIndex(domain)
	if err != nil {
		return nil, err
	}
	for _, k := range idx.Keys {
		if k.Kid == kid {
			return k.PubKey()
		}
	}
	return nil, fmt.Errorf("no key %s/%s", domain, kid)
}

func (r *httpResolver) Refresh(string) error { return nil }

func (r *httpResolver) ResolveInbox(domain string) (string, error) {
	idx, err := r.fetchIndex(domain)
	if err != nil {
		return "", err
	}
	return idx.Inbox, nil
}

func (r *httpResolver) ResolveTransport(domain, proto string) (string, bool, error) {
	return "", false, nil
}

type peer struct {
	domain string
	daemon *daemon.Daemon
	store  *store.Store
	srv    *httptest.Server
}

func newPeer(domain string, insecureHTTP *http.Client, resolver *httpResolver, handler daemon.MessageHandler) (*peer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(os.TempDir(), "custom-handler-"+domain+".db")
	os.Remove(dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store for %s: %w", domain, err)
	}
	d, err := daemon.New(daemon.Config{
		Domain: domain, Kid: "k1", Priv: priv,
		Store: st, Clock: clock.Real{}, Resolver: resolver, HTTP: insecureHTTP,
		MessageHandler: handler,
	})
	if err != nil {
		return nil, fmt.Errorf("construct daemon for %s: %w", domain, err)
	}
	srv := httptest.NewTLSServer(d)
	if err := d.FinalizeIndex(srv.URL+"/awp/inbox", nil); err != nil {
		return nil, fmt.Errorf("finalize index for %s: %w", domain, err)
	}
	return &peer{domain: domain, daemon: d, store: st, srv: srv}, nil
}

func (p *peer) close() {
	p.srv.Close()
	p.store.Close()
	os.Remove(filepath.Join(os.TempDir(), "custom-handler-"+p.domain+".db"))
}

func drainOutbox(ctx context.Context, d *daemon.Daemon) error {
	for {
		n, err := d.RunOutboxOnce(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	insecureHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local self-signed demo certs

	userResolver := &httpResolver{http: insecureHTTP, baseURLs: map[string]string{}}
	plannerResolver := &httpResolver{http: insecureHTTP, baseURLs: map[string]string{}}

	// This is the whole point: real logic instead of the reference
	// ack-then-reply default. No ack is sent at all here — a handler is
	// free to respond however it wants, including not immediately.
	plannerHandler := func(_ context.Context, env *envelope.Envelope, send daemon.SendFunc) error {
		var body struct {
			Type string `json:"type"`
			Goal string `json:"goal"`
		}
		if err := json.Unmarshal(env.Body, &body); err != nil || body.Type != "task" {
			_, err := send("error", json.RawMessage(`{"type":"data","schema":null,"data":{"code":"unsupported_body","detail":"want a task body","retryable":false}}`))
			return err
		}
		answer := fmt.Sprintf("done: %s", strings.ToUpper(body.Goal))
		_, err := send("reply", json.RawMessage(fmt.Sprintf(`{"type":"text","text":%q}`, answer)))
		return err
	}

	user, err := newPeer("user.example", insecureHTTP, userResolver, nil) // default handler; user.example never receives a `message`
	if err != nil {
		return err
	}
	defer user.close()
	planner, err := newPeer("planner.example", insecureHTTP, plannerResolver, plannerHandler)
	if err != nil {
		return err
	}
	defer planner.close()

	userResolver.baseURLs["planner.example"] = planner.srv.URL
	plannerResolver.baseURLs["user.example"] = user.srv.URL

	thread := envelope.NewID()
	msg, err := user.daemon.Send("message", "planner.example", thread, nil,
		json.RawMessage(`{"type":"task","goal":"book a table for four on friday"}`))
	if err != nil {
		return fmt.Errorf("user send message: %w", err)
	}
	fmt.Printf("user -> planner   task    %s\n", msg.ID)
	if err := drainOutbox(ctx, user.daemon); err != nil {
		return fmt.Errorf("user deliver message: %w", err)
	}

	if _, err := planner.daemon.ProcessInboundOnce(ctx); err != nil {
		return fmt.Errorf("planner process inbound: %w", err)
	}
	if err := drainOutbox(ctx, planner.daemon); err != nil {
		return fmt.Errorf("planner deliver reply: %w", err)
	}

	if _, err := user.daemon.ProcessInboundOnce(ctx); err != nil {
		return fmt.Errorf("user process inbound: %w", err)
	}

	msgs, err := user.store.ThreadMessages(thread)
	if err != nil {
		return err
	}
	fmt.Println("\nuser's view of the thread:")
	for _, m := range msgs {
		var env envelope.Envelope
		if err := json.Unmarshal(m.Envelope, &env); err != nil {
			return err
		}
		fmt.Printf("  %-7s from=%-16s %s\n", env.Kind, env.From, env.Body)
	}
	fmt.Println("\nnote: no `ack` anywhere above — the custom handler chose to skip it and reply directly.")
	return nil
}
