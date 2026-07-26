// Command agent-messaging is the async, agent-to-agent side of AWP: two
// independent domains — alice.example and bob.example — each run a real
// daemon.Daemon (the type cmd/awpd wraps), and alice sends a signed
// `message` envelope that bob's default handler acks and replies to,
// after which alice closes the thread. This is core §2.1's full envelope
// vocabulary and the exact flow Phase 4's milestone ("message -> ack ->
// reply -> close, signatures verified, thread state correct on both
// sides") checks for.
//
// Unlike hello-tool and stateful-tool-delegation, key resolution here is
// real HTTP+HTTPS fetching of each side's /.well-known/awp.json — the
// only thing substituted for a production deployment is DNS itself (each
// domain's "real" address is a local variable instead of a DNS record).
//
// awpd drives inbound processing and outbound delivery on a timer
// (internal/daemon's ProcessInboundOnce / RunOutboxOnce, ticked from
// cmd/awpd/main.go). This example calls the same two methods directly and
// explicitly, once per step, so the sequence below is deterministic and
// printable instead of racing a background goroutine.
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

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// httpResolver resolves any domain by fetching its real
// /.well-known/awp.json over HTTPS and verifying its self-signature —
// the same TOFU trust model internal/keyresolver.HTTPResolver uses, minus
// its bbolt-backed cache (fine for a handful of calls in a demo; a real
// long-running daemon needs the cache so it isn't refetching on every
// signature check).
type httpResolver struct {
	http     *http.Client
	baseURLs map[string]string // domain -> real base URL; substitutes for DNS in this demo
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

func (r *httpResolver) Refresh(string) error { return nil } // nothing cached to invalidate

func (r *httpResolver) ResolveInbox(domain string) (string, error) {
	idx, err := r.fetchIndex(domain)
	if err != nil {
		return "", err
	}
	return idx.Inbox, nil
}

func (r *httpResolver) ResolveTransport(domain, proto string) (string, bool, error) {
	idx, err := r.fetchIndex(domain)
	if err != nil {
		return "", false, err
	}
	for _, t := range idx.Transports {
		if t.Proto == proto {
			return t.Endpoint, true, nil
		}
	}
	return "", false, nil
}

type peer struct {
	domain string
	daemon *daemon.Daemon
	store  *store.Store
	srv    *httptest.Server
}

func newPeer(domain string, insecureHTTP *http.Client, resolver *httpResolver) (*peer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(os.TempDir(), "agent-messaging-"+domain+".db")
	os.Remove(dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open store for %s: %w", domain, err)
	}
	d, err := daemon.New(daemon.Config{
		Domain: domain, Kid: "k1", Priv: priv,
		Store: st, Clock: clock.Real{}, Resolver: resolver, HTTP: insecureHTTP,
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
	os.Remove(filepath.Join(os.TempDir(), "agent-messaging-"+p.domain+".db"))
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// drainOutbox calls RunOutboxOnce until a tick delivers nothing, since a
// single tick starts at most one in-flight delivery per destination
// domain (see outbox.ProcessDue) — this example wants everything queued
// so far to land before printing thread state.
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

func run() error {
	ctx := context.Background()
	insecureHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local self-signed demo certs

	aliceResolver := &httpResolver{http: insecureHTTP, baseURLs: map[string]string{}}
	bobResolver := &httpResolver{http: insecureHTTP, baseURLs: map[string]string{}}

	alice, err := newPeer("alice.example", insecureHTTP, aliceResolver)
	if err != nil {
		return err
	}
	defer alice.close()
	bob, err := newPeer("bob.example", insecureHTTP, bobResolver)
	if err != nil {
		return err
	}
	defer bob.close()

	// Substitutes for DNS: each side's resolver now knows the other's
	// real (local) address, exactly as DNS + core §1.1's https://{domain}
	// default would in production.
	aliceResolver.baseURLs["bob.example"] = bob.srv.URL
	bobResolver.baseURLs["alice.example"] = alice.srv.URL

	threadID := envelope.NewID()
	fmt.Printf("thread %s\n\n", threadID)

	// 1. alice -> bob: message
	msg, err := alice.daemon.Send("message", "bob.example", threadID, nil,
		json.RawMessage(`{"type":"text","text":"got a minute to review the AWP spec?"}`))
	if err != nil {
		return fmt.Errorf("alice send message: %w", err)
	}
	fmt.Printf("alice -> bob   message  %s\n", msg.ID)
	if err := drainOutbox(ctx, alice.daemon); err != nil {
		return fmt.Errorf("alice deliver message: %w", err)
	}

	// 2. bob receives it; the reference default handler for `message` acks
	// then replies (internal/daemon.handleMessage) — a real agent would
	// plug in its own logic here instead. Both land in the same outbox
	// tick, but ProcessDue only ever starts one in-flight delivery per
	// destination domain per call (real awpd calls RunOutboxOnce on a
	// timer, so the second catches the next tick) — drainOutbox loops
	// until nothing is left, standing in for "wait for the next tick".
	if _, err := bob.daemon.ProcessInboundOnce(ctx); err != nil {
		return fmt.Errorf("bob process inbound: %w", err)
	}
	if err := drainOutbox(ctx, bob.daemon); err != nil {
		return fmt.Errorf("bob deliver ack+reply: %w", err)
	}

	// 3. alice receives bob's ack and reply.
	if _, err := alice.daemon.ProcessInboundOnce(ctx); err != nil {
		return fmt.Errorf("alice process inbound: %w", err)
	}
	replyID, err := printThread("alice", alice.store, threadID)
	if err != nil {
		return err
	}

	// 4. alice closes the thread, in reply to bob's reply.
	closeEnv, err := alice.daemon.Send("close", "bob.example", threadID, &replyID,
		json.RawMessage(`{"type":"text","text":"thanks, that's everything"}`))
	if err != nil {
		return fmt.Errorf("alice send close: %w", err)
	}
	fmt.Printf("\nalice -> bob   close    %s\n", closeEnv.ID)
	if err := drainOutbox(ctx, alice.daemon); err != nil {
		return fmt.Errorf("alice deliver close: %w", err)
	}
	if _, err := bob.daemon.ProcessInboundOnce(ctx); err != nil {
		return fmt.Errorf("bob process inbound: %w", err)
	}

	fmt.Println()
	if _, err := printThread("alice", alice.store, threadID); err != nil {
		return err
	}
	fmt.Println()
	if _, err := printThread("bob", bob.store, threadID); err != nil {
		return err
	}
	return nil
}

// printThread prints one side's recorded view of the thread and returns
// the id of its last `reply` envelope, for chaining a close's in_reply_to.
func printThread(who string, st *store.Store, threadID string) (string, error) {
	thread, ok, err := st.GetThread(threadID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("%s: thread %s not found", who, threadID)
	}
	msgs, err := st.ThreadMessages(threadID)
	if err != nil {
		return "", err
	}
	fmt.Printf("%s's view of the thread (closed=%v):\n", who, thread.Closed)
	var lastReplyID string
	for _, m := range msgs {
		var env envelope.Envelope
		if err := json.Unmarshal(m.Envelope, &env); err != nil {
			return "", err
		}
		fmt.Printf("  %-7s from=%-16s %s\n", env.Kind, env.From, env.Body)
		if env.Kind == "reply" {
			lastReplyID = env.ID
		}
	}
	return lastReplyID, nil
}
