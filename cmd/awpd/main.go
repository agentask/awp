// Command awpd is the AWP reference daemon: it serves a domain's signed
// index and inbox, and drives outbound delivery + inbound processing. See
// internal/daemon for the actual wiring; this is a thin CLI/process shell
// around it, per CLAUDE.md's "single daemon binary" decision.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/outbox"
	"github.com/agentask/awp/internal/store"
)

func main() {
	domain := flag.String("domain", "", "this domain's principal name (required)")
	kid := flag.String("kid", "", "this domain's active signing key id (required)")
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	dataDir := flag.String("data", "./awpd-data", "directory for the bbolt store and key file")
	tickInterval := flag.Duration("tick", time.Second, "outbox/inbound processing tick interval")
	resolveBaseURL := flag.String("resolve-base-url", "", "override the base URL ALL domain-index resolution uses (local/dev/self-test only; production leaves this unset and resolves https://{domain} per domain)")
	flag.Parse()

	if *domain == "" || *kid == "" {
		fmt.Fprintln(os.Stderr, "awpd: -domain and -kid are required")
		os.Exit(2)
	}

	if err := run(*domain, *kid, *addr, *dataDir, *tickInterval, *resolveBaseURL); err != nil {
		log.Fatalf("awpd: %v", err)
	}
}

func run(domain, kid, addr, dataDir string, tick time.Duration, resolveBaseURL string) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	priv, err := loadOrCreateKey(filepath.Join(dataDir, "identity.pem"))
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}

	st, err := store.Open(filepath.Join(dataDir, "awpd.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if recovered, err := st.InboundBootRecovery(); err != nil {
		return fmt.Errorf("inbound boot recovery: %w", err)
	} else if recovered > 0 {
		log.Printf("awpd: recovered %d in-flight inbound envelope(s)", recovered)
	}
	if recovered, err := st.BootRecovery(time.Now()); err != nil {
		return fmt.Errorf("outbox boot recovery: %w", err)
	} else if recovered > 0 {
		log.Printf("awpd: recovered %d in-flight outbound envelope(s)", recovered)
	}

	resolver := &keyresolver.HTTPResolver{Store: st, Clock: clock.Real{}}
	if resolveBaseURL != "" {
		resolver.BaseURL = func(string) string { return resolveBaseURL }
	}
	d, err := daemon.New(daemon.Config{
		Domain:    domain,
		Kid:       kid,
		Priv:      priv,
		Store:     st,
		Clock:     clock.Real{},
		Resolver:  resolver,
		OutboxCfg: outbox.DefaultConfig(),
	})
	if err != nil {
		return fmt.Errorf("construct daemon: %w", err)
	}

	// NOTE: the AWP core spec mandates HTTPS as the transport floor (core
	// §6). This reference binary listens plain HTTP for local/dev use;
	// operators MUST terminate TLS in front of it (reverse proxy) or this
	// binary needs a -tls-cert/-tls-key flag added before any non-trusted
	// deployment. Flagging rather than silently shipping an insecure
	// default that looks production-ready.
	inboxURL := "http://" + addr + "/awp/inbox"
	// awp/1 (QUIC) is not wired into cmd/awpd yet — see docs/experiments.md.
	// FinalizeIndex(nil transports) advertises HTTPS-only, which is exactly
	// what this binary currently speaks.
	if err := d.FinalizeIndex(inboxURL, nil); err != nil {
		return fmt.Errorf("finalize index: %w", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runTicker(ctx, d, tick)

	log.Printf("awpd: domain=%s listening on %s", domain, addr)
	server := &http.Server{Handler: d}
	return server.Serve(ln)
}

func runTicker(ctx context.Context, d *daemon.Daemon, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := d.ProcessInboundOnce(ctx); err != nil {
				log.Printf("awpd: inbound processing error: %v", err)
			}
			if _, err := d.RunOutboxOnce(ctx); err != nil {
				log.Printf("awpd: outbox delivery error: %v", err)
			}
		}
	}
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil || len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%s: not a valid ed25519 private key PEM", path)
		}
		return ed25519.PrivateKey(block.Bytes), nil
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "AWP ED25519 PRIVATE KEY", Bytes: priv}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return priv, nil
}
