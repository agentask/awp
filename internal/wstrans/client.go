package wstrans

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// EndpointResolver resolves a domain to its awp-ws/1 endpoint (a wss://
// URL), per the signed index's `transports` field (core §1.1,
// awp-ws-v0.1.md §2). ok=false means the domain doesn't advertise
// awp-ws/1 — callers MUST fall back per awp-ws-v0.1.md §5 rule 2, never
// treat it as an error to retry.
type EndpointResolver func(domain string) (endpoint string, ok bool, err error)

// Sender implements outbox.Sender over awp-ws/1. Connections are reused
// across sends to the same endpoint (awp-ws-v0.1.md §4: "long-lived and
// SHOULD be reused"); a connection that errors is dropped so the next
// send redials.
type Sender struct {
	// TLSConfig is the base client TLS config (RootCAs per deployment
	// trust policy). ServerName is set per dial from the resolved
	// endpoint's own host (wstrans.Dial), so it should be left unset here.
	TLSConfig       *tls.Config
	ResolveEndpoint EndpointResolver
	DialTimeout     time.Duration

	mu    sync.Mutex
	conns map[string]*clientConn // endpoint -> live connection
}

func (s *Sender) dialTimeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return 10 * time.Second
}

// Send implements outbox.Sender. WebSocket status messages never carry
// Retry-After (awp-ws-v0.1.md §3's StatusFrame has no such field —
// that's an HTTPS/awp-sig concept), so retryAfter/hasRetryAfter are
// always zero/false, identically to internal/quictrans.Sender.
func (s *Sender) Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	endpoint, ok, err := s.ResolveEndpoint(domain)
	if err != nil {
		return 0, 0, false, fmt.Errorf("wstrans: resolve awp-ws/1 endpoint for %s: %w", domain, err)
	}
	if !ok {
		return 0, 0, false, fmt.Errorf("wstrans: %s advertises no awp-ws/1 transport", domain)
	}

	cc, err := s.getConn(endpoint)
	if err != nil {
		return 0, 0, false, err
	}

	sf, err := cc.send(ctx, raw)
	if err != nil {
		s.dropConn(endpoint)
		return 0, 0, false, err
	}
	return sf.Status, 0, false, nil
}

func (s *Sender) getConn(endpoint string) (*clientConn, error) {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = map[string]*clientConn{}
	}
	if cc, ok := s.conns[endpoint]; ok && !cc.isClosed() {
		s.mu.Unlock()
		return cc, nil
	}
	s.mu.Unlock()

	conn, err := Dial(endpoint, s.TLSConfig, s.dialTimeout())
	if err != nil {
		return nil, fmt.Errorf("wstrans: dial %s: %w", endpoint, err)
	}
	cc := newClientConn(conn)

	s.mu.Lock()
	s.conns[endpoint] = cc
	s.mu.Unlock()
	return cc, nil
}

func (s *Sender) dropConn(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, endpoint)
}

// Close closes every cached connection.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for endpoint, cc := range s.conns {
		_ = cc.conn.Close()
		delete(s.conns, endpoint)
	}
	return nil
}

// clientConn multiplexes many concurrent sends over one WebSocket
// connection (awp-ws-v0.1.md §4: "one connection carries many envelopes,
// correlated by id") — unlike internal/quictrans, which gets this for
// free from one QUIC stream per envelope, a WebSocket connection is a
// single ordered byte stream with no independent sub-streams, so
// responses are matched to requests by the envelope id already present
// in every status message.
type clientConn struct {
	conn *Conn

	writeMu sync.Mutex

	pendingMu sync.Mutex
	pending   map[string]chan StatusFrame

	closed  chan struct{}
	readErr error
}

func newClientConn(conn *Conn) *clientConn {
	cc := &clientConn{
		conn:    conn,
		pending: map[string]chan StatusFrame{},
		closed:  make(chan struct{}),
	}
	go cc.readLoop()
	return cc
}

func (cc *clientConn) isClosed() bool {
	select {
	case <-cc.closed:
		return true
	default:
		return false
	}
}

// extractEnvelopeID peeks at raw's top-level "id" field without a full
// envelope.Envelope unmarshal — this package deliberately doesn't import
// internal/envelope, mirroring internal/quictrans's own independence
// from envelope-level knowledge (the QUIC binding never needs this
// because one stream already IS the correlation; this binding does).
func extractEnvelopeID(raw []byte) (string, error) {
	var e struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", fmt.Errorf("wstrans: envelope has no readable \"id\" field: %w", err)
	}
	if e.ID == "" {
		return "", fmt.Errorf("wstrans: envelope has an empty \"id\" field")
	}
	return e.ID, nil
}

func (cc *clientConn) send(ctx context.Context, raw []byte) (StatusFrame, error) {
	id, err := extractEnvelopeID(raw)
	if err != nil {
		return StatusFrame{}, err
	}

	ch := make(chan StatusFrame, 1)
	cc.pendingMu.Lock()
	if _, exists := cc.pending[id]; exists {
		cc.pendingMu.Unlock()
		return StatusFrame{}, fmt.Errorf("wstrans: envelope %s is already in flight on this connection", id)
	}
	cc.pending[id] = ch
	cc.pendingMu.Unlock()
	defer func() {
		cc.pendingMu.Lock()
		delete(cc.pending, id)
		cc.pendingMu.Unlock()
	}()

	cc.writeMu.Lock()
	err = writeFrame(cc.conn, opcodeBinary, raw, true) // masked: client -> server (RFC 6455 §5.3)
	cc.writeMu.Unlock()
	if err != nil {
		return StatusFrame{}, fmt.Errorf("wstrans: send envelope frame: %w", err)
	}

	select {
	case sf := <-ch:
		return sf, nil
	case <-ctx.Done():
		return StatusFrame{}, ctx.Err()
	case <-cc.closed:
		return StatusFrame{}, fmt.Errorf("wstrans: connection closed while awaiting status for %s: %w", id, cc.readErr)
	}
}

// readLoop demultiplexes incoming status messages by id until the
// connection errors or the peer closes it, dispatching each to whichever
// send call is waiting on it. A status message for an id nobody is
// waiting on (e.g. a duplicate, or the waiter already gave up on
// ctx.Done()) is dropped — there is nothing else to do with it.
func (cc *clientConn) readLoop() {
	defer close(cc.closed)
	for {
		// readFrame returns a non-nil err for every opcode other than
		// text/binary (frame.go's switch) — Close/ping/pong/reserved all
		// end the loop here, captured in readErr for send()'s callers.
		_, payload, err := readFrame(cc.conn)
		if err != nil {
			cc.readErr = err
			return
		}
		var sf StatusFrame
		if err := json.Unmarshal(payload, &sf); err != nil {
			continue // malformed status message: nothing to correlate it to
		}
		cc.pendingMu.Lock()
		ch, ok := cc.pending[sf.ID]
		cc.pendingMu.Unlock()
		if ok {
			ch <- sf
		}
	}
}
