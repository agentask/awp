// Command awpd is the AWP reference daemon: it serves a domain's signed
// index and inbox, and drives outbound delivery + inbound processing. See
// internal/daemon for the actual wiring; this is a thin CLI/process shell
// around it, per CLAUDE.md's "single daemon binary" decision.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/daemon"
	"github.com/agentask/awp/internal/delegation"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/keyresolver"
	"github.com/agentask/awp/internal/manifest"
	"github.com/agentask/awp/internal/outbox"
	"github.com/agentask/awp/internal/store"
)

// runConfig bundles awpd's CLI flags — kept as a struct rather than a
// growing positional parameter list, since new flags keep arriving as
// operational gaps get closed.
type runConfig struct {
	domain, kid, addr, dataDir string
	tick                       time.Duration
	resolveBaseURL             string
	tlsCertPath, tlsKeyPath    string
	resolveInsecure            bool
	quicAddr                   string
	quicDialTimeout            time.Duration
	demoEchoTool               bool
	deadRetention              time.Duration
}

func main() {
	cfg := runConfig{}
	flag.StringVar(&cfg.domain, "domain", "", "this domain's principal name (required)")
	flag.StringVar(&cfg.kid, "kid", "", "this domain's active signing key id (required)")
	flag.StringVar(&cfg.addr, "addr", "127.0.0.1:8443", "HTTPS listen address")
	flag.StringVar(&cfg.dataDir, "data", "./awpd-data", "directory for the bbolt store and key file")
	flag.DurationVar(&cfg.tick, "tick", time.Second, "outbox/inbound processing tick interval")
	flag.StringVar(&cfg.resolveBaseURL, "resolve-base-url", "", "override the base URL ALL domain-index resolution uses (local/dev/self-test only; production leaves this unset and resolves https://{domain} per domain)")
	flag.StringVar(&cfg.tlsCertPath, "tls-cert", "", "path to a PEM-encoded TLS certificate (production; e.g. from Let's Encrypt/your own CA)")
	flag.StringVar(&cfg.tlsKeyPath, "tls-key", "", "path to the PEM-encoded private key matching -tls-cert")
	flag.BoolVar(&cfg.resolveInsecure, "resolve-insecure", false, "skip TLS certificate verification when THIS daemon resolves domain indexes or dials awp/1 peers (local/dev/self-test only; never set this in production)")
	flag.StringVar(&cfg.quicAddr, "quic-addr", "", "awp/1 (QUIC) listen address; empty disables QUIC and advertises HTTPS-only, per awp-quic §2")
	flag.DurationVar(&cfg.quicDialTimeout, "quic-dial-timeout", 5*time.Second, "timeout dialing a peer's awp/1 endpoint before falling back to HTTPS")
	flag.BoolVar(&cfg.demoEchoTool, "demo-echo-tool", false, "register a demo kind:tool entity (\"echo\") that returns its verified caller + input — for trying out sync tool calls; not registered by default")
	flag.DurationVar(&cfg.deadRetention, "dead-retention", daemon.DefaultDeadRetention, "how long dead-lettered outbound envelopes are kept before hourly GC deletes them (awpd-outbox §3 outbox.dead_retention)")
	flag.Parse()

	if cfg.domain == "" || cfg.kid == "" {
		fmt.Fprintln(os.Stderr, "awpd: -domain and -kid are required")
		os.Exit(2)
	}
	if (cfg.tlsCertPath == "") != (cfg.tlsKeyPath == "") {
		fmt.Fprintln(os.Stderr, "awpd: -tls-cert and -tls-key must be given together")
		os.Exit(2)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("awpd: %v", err)
	}
}

func run(cfg runConfig) error {
	if err := os.MkdirAll(cfg.dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	priv, err := loadOrCreateKey(filepath.Join(cfg.dataDir, "identity.pem"))
	if err != nil {
		return fmt.Errorf("load identity key: %w", err)
	}

	st, err := store.Open(filepath.Join(cfg.dataDir, "awpd.db"))
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
	if cfg.resolveBaseURL != "" {
		resolver.BaseURL = func(string) string { return cfg.resolveBaseURL }
	}
	if cfg.resolveInsecure {
		resolver.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // explicit opt-in dev flag
	}

	// core §6 mandates HTTPS as the transport floor. This binary always
	// terminates real TLS: -tls-cert/-tls-key for production (a cert your
	// peers' WebPKI trust), or an ephemeral self-signed certificate
	// persisted under dataDir for local/dev/self-test use (peers doing
	// real WebPKI validation will reject it — that's correct, not a bug;
	// use -tls-cert/-tls-key for anything real).
	cert, err := loadOrCreateTLSCert(cfg.dataDir, cfg.domain, cfg.tlsCertPath, cfg.tlsKeyPath)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	daemonCfg := daemon.Config{
		Domain:        cfg.domain,
		Kid:           cfg.kid,
		Priv:          priv,
		Store:         st,
		Clock:         clock.Real{},
		Resolver:      resolver,
		OutboxCfg:     outbox.DefaultConfig(),
		DeadRetention: cfg.deadRetention,
	}
	if cfg.quicAddr != "" {
		clientTLS := &tls.Config{NextProtos: []string{"awp/1"}}
		if cfg.resolveInsecure {
			clientTLS.InsecureSkipVerify = true //nolint:gosec // explicit opt-in dev flag
		}
		daemonCfg.QUIC = &daemon.QUICConfig{
			ListenAddr:        cfg.quicAddr,
			ServerTLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"awp/1"}},
			ClientTLSConfig:   clientTLS,
			ClientDialTimeout: cfg.quicDialTimeout,
			ClientQUICConfig:  &quic.Config{},
		}
	}

	d, err := daemon.New(daemonCfg)
	if err != nil {
		return fmt.Errorf("construct daemon: %w", err)
	}

	var transports []identity.Transport
	if cfg.quicAddr != "" {
		transports = []identity.Transport{{Proto: "awp/1", Endpoint: d.QUICAddr()}}
	}
	inboxURL := "https://" + cfg.addr + "/awp/inbox"
	if err := d.FinalizeIndex(inboxURL, transports); err != nil {
		return fmt.Errorf("finalize index: %w", err)
	}

	if cfg.demoEchoTool {
		baseURL := "https://" + cfg.addr
		if err := d.RegisterTool(baseURL, daemon.Tool{
			Manifest: &manifest.Manifest{
				Awp: "0.1", Name: cfg.domain + "#echo", Kind: "tool", Version: "1.0.0",
				Description:  "Demo tool: returns the verified caller principal and the request body it was sent.",
				IO:           manifest.IOSchema{Input: []byte(`{"type":"object"}`), Output: []byte(`{"type":"object"}`)},
				Distribution: manifest.Distribution{Hosted: &manifest.Hosted{}},
				State:        "stateless",
				Auth:         manifest.Auth{Sig: "required"},
				Pricing:      []byte("null"),
			},
			Handler: func(_ context.Context, caller string, _ []delegation.Link, input json.RawMessage) (json.RawMessage, *apperr.Error) {
				out, err := json.Marshal(map[string]any{"caller": caller, "echo": input})
				if err != nil {
					return nil, &apperr.Error{Code: apperr.CodeInternal, Detail: err.Error()}
				}
				return out, nil
			},
		}); err != nil {
			return fmt.Errorf("register demo echo tool: %w", err)
		}
		log.Printf("awpd: registered demo tool %s#echo at %s/awp/tools/echo", cfg.domain, baseURL)
	}

	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.addr, err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runTicker(ctx, d, cfg.tick)
	go runGCTicker(ctx, d, time.Hour) // awpd-store §2: "GC: hourly cursor scan"
	if cfg.quicAddr != "" {
		go func() {
			if err := d.ServeQUIC(ctx); err != nil {
				log.Printf("awpd: awp/1 server error: %v", err)
			}
		}()
		log.Printf("awpd: domain=%s listening on %s (TLS) and %s (awp/1)", cfg.domain, cfg.addr, d.QUICAddr())
	} else {
		log.Printf("awpd: domain=%s listening on %s (TLS)", cfg.domain, cfg.addr)
	}

	server := &http.Server{Handler: d}
	return server.Serve(tlsLn)
}

// loadOrCreateTLSCert loads an operator-provided cert/key pair if given,
// otherwise loads (or generates and persists) an ephemeral self-signed
// ed25519 certificate for domain under dataDir, so this binary always
// speaks real TLS even with zero configuration. The same certificate backs
// both the HTTPS listener and, if enabled, the awp/1 (QUIC) listener.
func loadOrCreateTLSCert(dataDir, domain, certPath, keyPath string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	selfCertPath := filepath.Join(dataDir, "tls-self-signed-cert.pem")
	selfKeyPath := filepath.Join(dataDir, "tls-self-signed-key.pem")
	if cert, err := tls.LoadX509KeyPair(selfCertPath, selfKeyPath); err == nil {
		return cert, nil
	}

	log.Printf("awpd: no -tls-cert/-tls-key given; generating a self-signed certificate for %q (local/dev/self-test only — peers doing real WebPKI validation will reject it)", domain)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal self-signed key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(selfCertPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", selfCertPath, err)
	}
	if err := os.WriteFile(selfKeyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", selfKeyPath, err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
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

func runGCTicker(ctx context.Context, d *daemon.Daemon, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			seenDeleted, deadDeleted, err := d.RunGCOnce()
			if err != nil {
				log.Printf("awpd: gc error: %v", err)
				continue
			}
			if seenDeleted > 0 || deadDeleted > 0 {
				log.Printf("awpd: gc: %d seen entries, %d dead letters deleted", seenDeleted, deadDeleted)
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
