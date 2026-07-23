package quictrans

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// EndpointResolver resolves a domain to its awp/1 endpoint (host:port),
// per the signed index's `transports` field (core §1.1, awp-quic §2).
// ok=false means the domain doesn't advertise awp/1 — callers MUST fall
// back to HTTPS (awp-quic §5 rule 2), never treat it as an error to retry.
type EndpointResolver func(domain string) (endpoint string, ok bool, err error)

// Sender implements outbox.Sender over `awp/1`. Connections are reused
// across sends to the same endpoint (awp-quic §4: "long-lived and SHOULD be
// reused"); a connection that errors is dropped so the next send redials.
type Sender struct {
	// TLSConfig is the base client TLS config (NextProtos MUST include
	// "awp/1"; RootCAs per deployment trust policy). ServerName is set per
	// dial from the resolved domain — SNI = the receiving domain
	// (awp-quic §1) — so it should be left unset here.
	TLSConfig       *tls.Config
	QUICConfig      *quic.Config
	ResolveEndpoint EndpointResolver
	DialTimeout     time.Duration

	mu    sync.Mutex
	conns map[string]*quic.Conn // endpoint -> live connection
}

func (s *Sender) dialTimeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return 10 * time.Second
}

// Send implements outbox.Sender. QUIC status frames never carry
// Retry-After (awp-quic §3's StatusFrame has no such field — that's an
// HTTPS/awp-sig concept), so retryAfter/hasRetryAfter are always zero/false.
func (s *Sender) Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	endpoint, ok, err := s.ResolveEndpoint(domain)
	if err != nil {
		return 0, 0, false, fmt.Errorf("quictrans: resolve awp/1 endpoint for %s: %w", domain, err)
	}
	if !ok {
		return 0, 0, false, fmt.Errorf("quictrans: %s advertises no awp/1 transport", domain)
	}

	conn, err := s.getConn(ctx, domain, endpoint)
	if err != nil {
		return 0, 0, false, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		s.dropConn(endpoint)
		return 0, 0, false, fmt.Errorf("quictrans: open stream to %s: %w", endpoint, err)
	}

	if err := writeFrame(stream, raw); err != nil {
		return 0, 0, false, fmt.Errorf("quictrans: send envelope frame to %s: %w", endpoint, err)
	}
	if err := stream.Close(); err != nil { // half-close: done writing (awp-quic §4)
		return 0, 0, false, fmt.Errorf("quictrans: half-close stream to %s: %w", endpoint, err)
	}

	respBuf, err := readFrame(stream)
	if err != nil {
		return 0, 0, false, fmt.Errorf("quictrans: read status frame from %s: %w", endpoint, err)
	}
	var sf StatusFrame
	if err := json.Unmarshal(respBuf, &sf); err != nil {
		return 0, 0, false, fmt.Errorf("quictrans: unmarshal status frame from %s: %w", endpoint, err)
	}
	return sf.Status, 0, false, nil
}

func (s *Sender) getConn(ctx context.Context, domain, endpoint string) (*quic.Conn, error) {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = map[string]*quic.Conn{}
	}
	if conn, ok := s.conns[endpoint]; ok {
		s.mu.Unlock()
		return conn, nil
	}
	s.mu.Unlock()

	tlsConf := s.TLSConfig.Clone()
	tlsConf.ServerName = domain // awp-quic §1: SNI = the receiving domain

	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, endpoint, tlsConf, s.QUICConfig)
	if err != nil {
		return nil, fmt.Errorf("quictrans: dial %s (%s): %w", endpoint, domain, err)
	}

	s.mu.Lock()
	s.conns[endpoint] = conn
	s.mu.Unlock()
	return conn, nil
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
	for endpoint, conn := range s.conns {
		_ = conn.CloseWithError(0, "closing")
		delete(s.conns, endpoint)
	}
	return nil
}
