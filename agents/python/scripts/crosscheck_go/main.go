// Command crosscheck_go is a real Go internal/daemon.Daemon, used only to
// prove pyawp actually interoperates with this repo's Go reference
// implementation — real ed25519 signatures and real JCS canonicalization
// on both sides, not two internally-consistent-but-mutually-untested
// implementations. Driven by scripts/crosscheck_go.py; see that script
// for the full two-directional check.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// httpResolver is the same minimal real-HTTP resolver
// examples/agent-messaging uses.
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

func main() {
	domain := flag.String("domain", "go-agent.local", "this daemon's domain")
	addr := flag.String("addr", "127.0.0.1:19001", "listen address")
	peerDomain := flag.String("peer-domain", "py-agent.local", "the pyawp node's domain")
	peerBaseURL := flag.String("peer-base-url", "http://127.0.0.1:19002", "the pyawp node's base URL (DNS stand-in)")
	runSeconds := flag.Int("run-seconds", 6, "how long to tick outbox/inbound before exiting")
	flag.Parse()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	dbPath := filepath.Join(os.TempDir(), "crosscheck-go-"+*domain+".db")
	os.Remove(dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		st.Close()
		os.Remove(dbPath)
	}()

	resolver := &httpResolver{http: http.DefaultClient, baseURLs: map[string]string{*peerDomain: *peerBaseURL}}

	msgHandler := func(_ context.Context, env *envelope.Envelope, send daemon.SendFunc) error {
		fmt.Printf("GO-RECEIVED from=%s kind=%s body=%s\n", env.From, env.Kind, string(env.Body))
		_, err := send("reply", json.RawMessage(`{"type":"text","text":"hello from the real Go daemon"}`))
		return err
	}

	d, err := daemon.New(daemon.Config{
		Domain: *domain, Kid: "k1", Priv: priv, Store: st,
		Clock: clock.Real{}, Resolver: resolver, MessageHandler: msgHandler,
	})
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := http.Serve(ln, d); err != nil && err != http.ErrServerClosed {
			log.Printf("serve: %v", err)
		}
	}()

	if err := d.FinalizeIndex("http://"+*addr+"/awp/inbox", nil); err != nil {
		log.Fatal(err)
	}
	fmt.Println("GO-READY")

	// Give the peer a moment to be resolvable, then send the opener.
	time.Sleep(300 * time.Millisecond)
	thread := envelope.NewID()
	openerEnv, err := d.Send("message", *peerDomain, thread, nil,
		json.RawMessage(`{"type":"text","text":"hello from the real Go daemon"}`))
	if err != nil {
		log.Printf("send opener: %v", err)
	}

	ctx := context.Background()
	deadline := time.Now().Add(time.Duration(*runSeconds) * time.Second)
	for time.Now().Before(deadline) {
		if _, err := d.RunOutboxOnce(ctx); err != nil {
			log.Printf("outbox: %v", err)
		}
		if _, err := d.ProcessInboundOnce(ctx); err != nil {
			log.Printf("inbound: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if openerEnv != nil {
		if rec, found, err := st.GetOutbox(openerEnv.ID); err != nil {
			fmt.Printf("GO-OPENER-STATUS: lookup error: %v\n", err)
		} else if !found {
			fmt.Println("GO-OPENER-STATUS: delivered (no longer in outbox)")
		} else {
			fmt.Printf("GO-OPENER-STATUS: state=%s attempts=%d next_at=%s last_err=%s dead_reason=%s\n",
				rec.State, rec.Attempts, rec.NextAt, rec.LastErr, rec.DeadReason)
		}
	}

	dead, err := st.ListDead()
	if err != nil {
		log.Printf("list dead: %v", err)
	}
	for _, rec := range dead {
		fmt.Printf("GO-DEAD-LETTER id=%s state=%s attempts=%d reason=%s last_err=%s\n",
			rec.ID, rec.State, rec.Attempts, rec.DeadReason, rec.LastErr)
	}
	fmt.Println("GO-DONE")
}
