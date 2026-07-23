// Package daemon wires internal/store, internal/inbox, internal/outbox,
// and internal/keyresolver into the reference `awpd` behavior: serve a
// signed domain index, accept envelopes, process them (thread bookkeeping
// plus a minimal default message handler), and deliver outbound envelopes.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/inbox"
	"github.com/agentask/awp/internal/outbox"
	"github.com/agentask/awp/internal/quictrans"
	"github.com/agentask/awp/internal/store"
)

// RFC3339Milli is core §0's timestamp format: RFC 3339 UTC, millisecond
// precision ("2026-07-21T09:14:03.512Z").
const RFC3339Milli = "2006-01-02T15:04:05.000Z"

// DefaultTTL is used for envelopes this daemon originates when the caller
// doesn't specify one.
const DefaultTTL = 3600

// Resolver is what a Daemon needs from a key resolver: signature
// verification key lookup (plugged directly into the inbox gate), inbox-URL
// discovery for outbound HTTPS delivery, and transport discovery for
// outbound awp/1 delivery. internal/keyresolver.HTTPResolver implements
// this.
type Resolver interface {
	inbox.KeyResolver
	ResolveInbox(domain string) (string, error)
	ResolveTransport(domain, proto string) (endpoint string, ok bool, err error)
}

// QUICConfig enables the awp/1 transport (awp-quic-v0.1.md). Its absence
// from Config means HTTPS-only (awp-quic §2), matching the spec's own
// framing of QUIC as a negotiated upgrade, never a replacement.
type QUICConfig struct {
	// ListenAddr is bound synchronously in New (e.g. "127.0.0.1:0" for an
	// ephemeral port in tests). Required.
	ListenAddr string
	// ServerTLSConfig must present a certificate for this domain and
	// advertise ALPN "awp/1".
	ServerTLSConfig *tls.Config
	// ClientTLSConfig is the base config used when this daemon dials
	// peers; ServerName is set per-dial from the resolved domain
	// (awp-quic §1: SNI = the receiving domain), so it should be left
	// unset here. NextProtos should include "awp/1"; RootCAs per
	// deployment trust policy.
	ClientTLSConfig *tls.Config
	// ClientDialTimeout bounds how long a dial to an unreachable/dead
	// awp/1 endpoint is allowed to hang before FallbackSender falls back
	// to HTTPS (awp-quic §5 rule 2). 0 uses quictrans.Sender's own default
	// (10s) — quic-go's own handshake-idle-timeout default is on the same
	// order, so a real deployment fronting flaky peers will usually want
	// this set explicitly, shorter than the outbox's own backoff cadence.
	ClientDialTimeout time.Duration
	// ClientQUICConfig is passed to quic.DialAddr for outbound dials; nil
	// uses quic-go's defaults.
	ClientQUICConfig *quic.Config
}

// Config configures a new Daemon.
type Config struct {
	Domain    string
	Kid       string
	Priv      ed25519.PrivateKey
	Store     *store.Store
	Clock     clock.Clock
	Resolver  Resolver
	HTTP      *http.Client // used for outbound HTTPS delivery; nil uses http.DefaultClient
	OutboxCfg outbox.Config
	QUIC      *QUICConfig // nil = HTTPS-only
}

// Daemon is a single AWP domain's running state: identity, store, inbox
// gate, and outbox sender, exposed as one http.Handler serving both
// /.well-known/awp.json and /awp/inbox — this IS what cmd/awpd runs. If
// QUIC is enabled, ServeQUIC must also be run by the caller (mirroring how
// the caller also runs the http.Server for the HTTP side).
type Daemon struct {
	Domain    string
	Kid       string
	priv      ed25519.PrivateKey
	Store     *store.Store
	Clock     clock.Clock
	Gate      *inbox.Gate
	Sender    outbox.Sender
	OutboxCfg outbox.Config

	mu    sync.Mutex
	index *identity.Index

	mux *http.ServeMux

	quicListener *quic.Listener
	quicServer   *quictrans.Server
	quicSender   *quictrans.Sender
}

// New constructs a Daemon with a fresh self-signed domain index (one active
// key, no inbox URL yet — call FinalizeIndex once the daemon's own address
// is known, e.g. after starting an httptest.Server or binding a real port).
func New(cfg Config) (*Daemon, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	pub := cfg.Priv.Public().(ed25519.PublicKey)

	idx := &identity.Index{
		Awp:     "0.1",
		Domain:  cfg.Domain,
		Updated: cfg.Clock.Now().UTC().Format(RFC3339Milli),
		Keys: []identity.Key{{
			Kid:     cfg.Kid,
			Alg:     "ed25519",
			Pub:     base64.RawURLEncoding.EncodeToString(pub),
			Created: cfg.Clock.Now().UTC().Format(RFC3339Milli),
		}},
	}
	if err := idx.Sign(cfg.Priv, cfg.Kid); err != nil {
		return nil, fmt.Errorf("daemon: sign initial index: %w", err)
	}

	gate := &inbox.Gate{
		Store: cfg.Store,
		Keys:  cfg.Resolver,
		Clock: cfg.Clock,
	}
	var sender outbox.Sender = &outbox.HTTPSender{
		Client:   cfg.HTTP,
		InboxURL: cfg.Resolver.ResolveInbox,
	}

	outboxCfg := cfg.OutboxCfg
	if outboxCfg.BackoffCap == 0 && outboxCfg.BackoffBase == 0 && outboxCfg.Workers == 0 {
		outboxCfg = outbox.DefaultConfig()
	}

	d := &Daemon{
		Domain:    cfg.Domain,
		Kid:       cfg.Kid,
		priv:      cfg.Priv,
		Store:     cfg.Store,
		Clock:     cfg.Clock,
		Gate:      gate,
		OutboxCfg: outboxCfg,
		index:     idx,
	}

	if cfg.QUIC != nil {
		ln, err := quic.ListenAddr(cfg.QUIC.ListenAddr, cfg.QUIC.ServerTLSConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("daemon: listen awp/1 on %s: %w", cfg.QUIC.ListenAddr, err)
		}
		d.quicListener = ln
		d.quicServer = &quictrans.Server{Gate: gate}
		d.quicSender = &quictrans.Sender{
			TLSConfig:   cfg.QUIC.ClientTLSConfig,
			QUICConfig:  cfg.QUIC.ClientQUICConfig,
			DialTimeout: cfg.QUIC.ClientDialTimeout,
			ResolveEndpoint: func(domain string) (string, bool, error) {
				return cfg.Resolver.ResolveTransport(domain, "awp/1")
			},
		}
		// awp-quic §5 rule 2: a failed QUIC attempt and a failed HTTPS
		// attempt are the same outbox transition — FallbackSender hides
		// the two-transport dance behind one Sender.Send call.
		sender = &quictrans.FallbackSender{Primary: d.quicSender, Fallback: sender}
	}
	d.Sender = sender

	d.buildMux()
	return d, nil
}

// QUICAddr returns the bound awp/1 listen address, or "" if QUIC is
// disabled. Needed to learn the actual port when ListenAddr used ":0".
func (d *Daemon) QUICAddr() string {
	if d.quicListener == nil {
		return ""
	}
	return d.quicListener.Addr().String()
}

// ServeQUIC accepts awp/1 connections until ctx is done or the listener is
// closed. Callers run this in a goroutine, exactly as they run the HTTP
// server for this Daemon's ServeHTTP.
func (d *Daemon) ServeQUIC(ctx context.Context) error {
	if d.quicServer == nil {
		return nil
	}
	return d.quicServer.Serve(ctx, d.quicListener)
}

// Close releases QUIC resources (listener and any cached outbound
// connections). A no-op if QUIC is disabled.
func (d *Daemon) Close() error {
	if d.quicSender != nil {
		_ = d.quicSender.Close()
	}
	if d.quicListener != nil {
		return d.quicListener.Close()
	}
	return nil
}

func (d *Daemon) buildMux() {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/awp.json", d.serveIndex)
	mux.Handle("/awp/inbox", d.Gate)
	d.mux = mux
}

// ServeHTTP makes Daemon itself a drop-in http.Handler for both endpoints.
func (d *Daemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mux.ServeHTTP(w, r)
}

func (d *Daemon) serveIndex(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	idx := d.index
	d.mu.Unlock()
	raw, err := json.Marshal(idx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// FinalizeIndex sets this domain's advertised inbox URL and transports
// (nil/empty means HTTPS-only, per awp-quic §2), and re-signs the index.
// Call once the daemon's own reachable address(es) are known (e.g. after
// httptest.NewServer(d) and/or QUICAddr()) and before any peer is expected
// to fetch /.well-known/awp.json.
func (d *Daemon) FinalizeIndex(inboxURL string, transports []identity.Transport) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.index.Inbox = inboxURL
	d.index.Transports = transports
	d.index.Updated = d.Clock.Now().UTC().Format(RFC3339Milli)
	return d.index.Sign(d.priv, d.Kid)
}

// Send builds, signs, and enqueues an envelope for delivery, and records it
// against the given thread on this daemon's own side. threadID is minted by
// the caller for a new thread (core §2.1: "ULID minted by the sender of the
// thread's first envelope") or carried over for subsequent envelopes.
func (d *Daemon) Send(kind, to, threadID string, inReplyTo *string, body json.RawMessage) (*envelope.Envelope, error) {
	now := d.Clock.Now()
	e := &envelope.Envelope{
		Awp:       "0.1",
		ID:        envelope.NewID(),
		Kind:      kind,
		From:      d.Domain,
		To:        to,
		Thread:    threadID,
		InReplyTo: inReplyTo,
		Ts:        now.UTC().Format(RFC3339Milli),
		TTL:       DefaultTTL,
		Body:      body,
	}
	if err := e.Sign(d.priv, d.Kid); err != nil {
		return nil, fmt.Errorf("daemon: sign outbound envelope: %w", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("daemon: marshal outbound envelope: %w", err)
	}
	if err := d.Store.EnqueueOutbound(e.ID, raw, now); err != nil {
		return nil, fmt.Errorf("daemon: enqueue outbound: %w", err)
	}
	if err := d.Store.RecordThreadEnvelope(threadID, to, e.ID, raw, now, kind == "close", d.Domain); err != nil {
		return nil, fmt.Errorf("daemon: record thread state: %w", err)
	}
	return e, nil
}

// RunOutboxOnce drains one tick of due outbound deliveries.
func (d *Daemon) RunOutboxOnce(ctx context.Context) (int, error) {
	return outbox.ProcessDue(ctx, d.Store, d.Clock, d.Sender, d.OutboxCfg, 100)
}

// ProcessInboundOnce claims and processes every currently-queued inbound
// envelope: records thread state and, for `message` envelopes, runs the
// default reference behavior (ack, then reply). Returns the number of
// envelopes processed and the first processing error encountered, if any
// (processing continues past errors — one bad envelope must not stall the
// queue).
func (d *Daemon) ProcessInboundOnce(ctx context.Context) (int, error) {
	claimed, err := d.Store.ClaimInbound(100)
	if err != nil {
		return 0, err
	}
	var firstErr error
	processed := 0
	for _, rec := range claimed {
		if err := d.processOne(ctx, rec); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		processed++
	}
	return processed, firstErr
}

func (d *Daemon) processOne(ctx context.Context, rec store.InboundRecord) error {
	defer func() { _ = d.Store.CompleteInbound(rec.ID) }()

	var env envelope.Envelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		return fmt.Errorf("daemon: unmarshal claimed envelope %s: %w", rec.ID, err)
	}

	ts, err := time.Parse(time.RFC3339, env.Ts)
	if err != nil {
		ts = d.Clock.Now()
	}
	if err := d.Store.RecordThreadEnvelope(env.Thread, env.From, env.ID, rec.Envelope, ts, env.Kind == "close", env.From); err != nil {
		return fmt.Errorf("daemon: record thread state for %s: %w", rec.ID, err)
	}

	if env.Kind != "message" {
		return nil
	}
	return d.handleMessage(ctx, &env)
}

// handleMessage is the reference default behavior for an inbound `message`:
// send an `ack`, then a `reply`. A real application would plug in its own
// handler here; this daemon has no business logic of its own to run, so it
// demonstrates the full envelope-kind vocabulary instead.
func (d *Daemon) handleMessage(_ context.Context, env *envelope.Envelope) error {
	ackBody := json.RawMessage(`{"type":"data","schema":null,"data":{}}`)
	if _, err := d.Send("ack", env.From, env.Thread, &env.ID, ackBody); err != nil {
		return fmt.Errorf("daemon: send ack for %s: %w", env.ID, err)
	}

	replyBody := json.RawMessage(`{"type":"text","text":"received"}`)
	if _, err := d.Send("reply", env.From, env.Thread, &env.ID, replyBody); err != nil {
		return fmt.Errorf("daemon: send reply for %s: %w", env.ID, err)
	}
	return nil
}
