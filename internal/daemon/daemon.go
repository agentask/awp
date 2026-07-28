// Package daemon wires internal/store, internal/inbox, internal/outbox,
// and internal/keyresolver into the reference `awpd` behavior: serve a
// signed domain index, accept envelopes, process them (thread bookkeeping
// plus a message handler — a minimal ack-then-reply default, or your own
// via Config.MessageHandler), and deliver outbound envelopes.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	"github.com/agentask/awp/internal/wstrans"
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
	ResolveWake(domain string) (endpoint string, ok bool, err error)
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

// WSConfig enables the awp-ws/1 transport (awp-ws-v0.1.md). Its absence
// from Config means this binding is not offered — HTTPS (and awp/1, if
// enabled) remain the only options, matching QUICConfig's own framing of
// a negotiated upgrade, never a replacement. Unlike QUICConfig, this
// binding needs no separate listener or bind address: it is one more
// handler mounted on the daemon's existing HTTPS mux (awp-ws-v0.1.md §0's
// whole point).
type WSConfig struct {
	// ClientTLSConfig is the base config used when this daemon dials
	// peers over awp-ws/1. RootCAs per deployment trust policy;
	// ServerName is set per-dial from the resolved endpoint's own host
	// (wstrans.Dial), so it should be left unset here.
	ClientTLSConfig *tls.Config
	// ClientDialTimeout bounds how long a dial to an unreachable/dead
	// awp-ws/1 endpoint is allowed to hang before FallbackSender falls
	// back to the next transport (awp-ws-v0.1.md §5 rule 2). 0 uses
	// wstrans.Sender's own default (10s).
	ClientDialTimeout time.Duration
	// Path is the HTTP path this daemon's WS upgrade handler is mounted
	// at. "" defaults to "/awp/ws".
	Path string
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
	WS        *WSConfig   // nil = awp-ws/1 not offered
	// DeadRetention is how long dead-lettered outbound records are kept
	// before RunGCOnce deletes them (awpd-outbox §3 `outbox.dead_retention`).
	// 0 uses the spec default (720h).
	DeadRetention time.Duration
	// MessageHandler processes each inbound `message` envelope. nil uses
	// defaultMessageHandler (ack, then a fixed reply) — the reference
	// behavior that demonstrates the envelope-kind vocabulary end to end.
	// A real agent sets this to its own logic; see docs/agent-guide.md.
	MessageHandler MessageHandler
	// DisableStreaming makes this daemon behave as an implementation that
	// has NOT adopted awp-streaming-v0.1.md: a stream_chunk body is
	// rejected with error(unsupported_body) per core §2.3/§9 instead of
	// being buffered/reassembled, and the index never advertises the
	// "awp-streaming-v0.1" capability. Default false — the reference
	// daemon adopts streaming.
	DisableStreaming bool
	// StreamChunkHandler, if set, is invoked once per stream_chunk that
	// becomes deliverable — in order, with no gaps (awp-streaming-v0.1.md
	// §4) — after this daemon's own reassembly buffering. nil means
	// chunks are still correctly reassembled (queryable after the fact via
	// Store.ThreadMessages, filtered by body.stream_id and sorted by
	// body.seq) but nothing is pushed to the application layer.
	StreamChunkHandler StreamChunkHandler
	// StreamBufferMaxAge bounds how long an incomplete stream's reassembly
	// buffer is kept before RunGCOnce reclaims it as abandoned
	// (awp-streaming-v0.1.md §5). 0 uses DefaultStreamBufferMaxAge (24h).
	StreamBufferMaxAge time.Duration
}

// StreamChunkHandler processes one reassembled, in-order, gap-free
// stream_chunk (awp-streaming-v0.1.md §4) — the streaming counterpart of
// MessageHandler. Returning an error surfaces it from ProcessInboundOnce
// but does not stop the queue from draining.
type StreamChunkHandler func(ctx context.Context, thread, streamID string, seq int, final bool, data json.RawMessage) error

// DefaultStreamBufferMaxAge is how long an incomplete stream's
// reassembly buffer survives before being treated as abandoned
// (awp-streaming-v0.1.md §5).
const DefaultStreamBufferMaxAge = 24 * time.Hour

// SendFunc sends one envelope in response to whatever inbound `message` a
// MessageHandler is currently processing. to/thread/in_reply_to are
// pre-bound to that message — the handler only chooses kind and body.
type SendFunc func(kind string, body json.RawMessage) (*envelope.Envelope, error)

// MessageHandler processes one inbound `message` envelope, using send to
// respond (zero, one, or several times — e.g. an `ack` immediately,
// followed by a `reply` once real work finishes). Returning an error
// surfaces it from ProcessInboundOnce but does not stop the queue from
// draining; one bad message must not stall the rest.
type MessageHandler func(ctx context.Context, env *envelope.Envelope, send SendFunc) error

// DefaultDeadRetention is awpd-outbox-v0.1.md §3's `outbox.dead_retention`
// default.
const DefaultDeadRetention = 720 * time.Hour

// Daemon is a single AWP domain's running state: identity, store, inbox
// gate, and outbox sender, exposed as one http.Handler serving both
// /.well-known/awp.json and /awp/inbox — this IS what cmd/awpd runs. If
// QUIC is enabled, ServeQUIC must also be run by the caller (mirroring how
// the caller also runs the http.Server for the HTTP side).
type Daemon struct {
	Domain         string
	Kid            string
	priv           ed25519.PrivateKey
	Store          *store.Store
	Clock          clock.Clock
	Gate           *inbox.Gate
	Sender         outbox.Sender
	OutboxCfg      outbox.Config
	DeadRetention  time.Duration
	MessageHandler MessageHandler

	DisableStreaming   bool
	StreamChunkHandler StreamChunkHandler
	StreamBufferMaxAge time.Duration

	mu    sync.Mutex
	index *identity.Index
	tools map[string]*registeredTool

	mux *http.ServeMux

	quicListener *quic.Listener
	quicServer   *quictrans.Server
	quicSender   *quictrans.Sender

	wsPath   string
	wsServer *wstrans.Server
	wsSender *wstrans.Sender
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
	if !cfg.DisableStreaming {
		// awp-capabilities-v0.1.md §1: advertise adoption of the
		// streaming extension so a caller (or the conformance CLI) can
		// discover it from the index instead of finding out by trying.
		idx.Capabilities = []string{"awp-streaming-v0.1"}
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
		Clock:    cfg.Clock,
		WakeURL:  cfg.Resolver.ResolveWake,
	}

	outboxCfg := cfg.OutboxCfg
	if outboxCfg.BackoffCap == 0 && outboxCfg.BackoffBase == 0 && outboxCfg.Workers == 0 {
		outboxCfg = outbox.DefaultConfig()
	}
	deadRetention := cfg.DeadRetention
	if deadRetention == 0 {
		deadRetention = DefaultDeadRetention
	}

	streamBufferMaxAge := cfg.StreamBufferMaxAge
	if streamBufferMaxAge == 0 {
		streamBufferMaxAge = DefaultStreamBufferMaxAge
	}

	d := &Daemon{
		Domain:             cfg.Domain,
		Kid:                cfg.Kid,
		priv:               cfg.Priv,
		Store:              cfg.Store,
		Clock:              cfg.Clock,
		Gate:               gate,
		OutboxCfg:          outboxCfg,
		DeadRetention:      deadRetention,
		MessageHandler:     cfg.MessageHandler,
		DisableStreaming:   cfg.DisableStreaming,
		StreamChunkHandler: cfg.StreamChunkHandler,
		StreamBufferMaxAge: streamBufferMaxAge,
		index:              idx,
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

	if cfg.WS != nil {
		path := cfg.WS.Path
		if path == "" {
			path = "/awp/ws"
		}
		d.wsPath = path
		d.wsServer = &wstrans.Server{Gate: gate}
		d.wsSender = &wstrans.Sender{
			TLSConfig:   cfg.WS.ClientTLSConfig,
			DialTimeout: cfg.WS.ClientDialTimeout,
			ResolveEndpoint: func(domain string) (string, bool, error) {
				return cfg.Resolver.ResolveTransport(domain, "awp-ws/1")
			},
		}
		// awp-ws-v0.1.md §5 rule 2 / §0's reference ordering: WebSocket is
		// tried before awp/1 before HTTPS — wrapping the QUIC-wrapped
		// sender here (built just above, whether or not QUIC is actually
		// enabled) achieves exactly that chain.
		sender = &wstrans.FallbackSender{Primary: d.wsSender, Fallback: sender}
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

// WSEndpoint converts baseHTTPSURL (this daemon's own externally
// reachable https:// address, e.g. what an httptest.Server or a real
// public listener produced) into the wss:// endpoint value for this
// daemon's transports[] entry — "" if WS is disabled. Mirrors QUICAddr()'s
// role for the awp/1 transport: the caller passes the result to
// FinalizeIndex.
func (d *Daemon) WSEndpoint(baseHTTPSURL string) string {
	if d.wsServer == nil {
		return ""
	}
	u, err := url.Parse(baseHTTPSURL)
	if err != nil {
		return ""
	}
	u.Scheme = "wss"
	u.Path = strings.TrimRight(u.Path, "/") + d.wsPath
	return u.String()
}

// Close releases QUIC and awp-ws/1 resources (listener/cached outbound
// connections). A no-op for whichever of them is disabled.
func (d *Daemon) Close() error {
	if d.quicSender != nil {
		_ = d.quicSender.Close()
	}
	if d.wsSender != nil {
		_ = d.wsSender.Close()
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
	mux.HandleFunc("/awp/manifests/", d.serveManifest)
	mux.HandleFunc("/awp/tools/", d.serveToolCall)
	if d.wsServer != nil {
		mux.HandleFunc(d.wsPath, d.wsServer.ServeHTTP)
	}
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

// RunGCOnce deletes expired `seen` entries (awpd-store §2) and
// past-retention dead-lettered outbound records (awpd-outbox §2 rule 7).
// A real deployment calls this on a slow cadence (e.g. hourly, per
// awpd-store §2's "GC: hourly cursor scan"); tests call it directly
// against an injected clock.
func (d *Daemon) RunGCOnce() (seenDeleted, deadDeleted, streamBuffersDeleted int, err error) {
	now := d.Clock.Now()
	seenDeleted, err = d.Store.GCSeen(now)
	if err != nil {
		return seenDeleted, 0, 0, fmt.Errorf("daemon: gc seen: %w", err)
	}
	deadDeleted, err = d.Store.GCDeadLetters(now, d.DeadRetention)
	if err != nil {
		return seenDeleted, deadDeleted, 0, fmt.Errorf("daemon: gc dead letters: %w", err)
	}
	streamBuffersDeleted, err = d.Store.GCStreamBuffers(now, d.StreamBufferMaxAge)
	if err != nil {
		return seenDeleted, deadDeleted, streamBuffersDeleted, fmt.Errorf("daemon: gc stream buffers: %w", err)
	}
	return seenDeleted, deadDeleted, streamBuffersDeleted, nil
}

// ProcessInboundOnce claims and processes every currently-queued inbound
// envelope: records thread state and, for `message` envelopes, runs
// Config.MessageHandler (or the ack-then-reply default when unset).
// Returns the number of envelopes processed and the first processing
// error encountered, if any (processing continues past errors — one bad
// envelope must not stall the queue).
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

	if handled, err := d.tryProcessStreamChunk(ctx, &env); handled {
		return err
	}

	if env.Kind != "message" {
		return nil
	}
	handler := d.MessageHandler
	if handler == nil {
		handler = defaultMessageHandler
	}
	send := func(kind string, body json.RawMessage) (*envelope.Envelope, error) {
		return d.Send(kind, env.From, env.Thread, &env.ID, body)
	}
	return handler(ctx, &env, send)
}

// defaultMessageHandler is the reference behavior for an inbound `message`
// when Config.MessageHandler is unset: send an `ack`, then a `reply`. This
// daemon has no business logic of its own to run, so it demonstrates the
// full envelope-kind vocabulary instead — a real agent sets
// Config.MessageHandler to its own logic (see docs/agent-guide.md).
func defaultMessageHandler(_ context.Context, env *envelope.Envelope, send SendFunc) error {
	ackBody := json.RawMessage(`{"type":"data","schema":null,"data":{}}`)
	if _, err := send("ack", ackBody); err != nil {
		return fmt.Errorf("daemon: send ack for %s: %w", env.ID, err)
	}

	replyBody := json.RawMessage(`{"type":"text","text":"received"}`)
	if _, err := send("reply", replyBody); err != nil {
		return fmt.Errorf("daemon: send reply for %s: %w", env.ID, err)
	}
	return nil
}
