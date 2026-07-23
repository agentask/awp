package quictrans

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/inbox"
)

// Server accepts `awp/1` connections and runs every envelope frame through
// the SAME inbox.Gate an HTTPS listener would use — awp-quic §5 rule 1
// (gate equivalence) holds by construction: there is only one Gate.Accept,
// called from two transport adapters.
type Server struct {
	Gate *inbox.Gate
	// Logf receives non-fatal per-connection/per-stream errors (a peer
	// disconnecting mid-stream is normal, not a bug). Defaults to
	// discarding.
	Logf func(format string, args ...any)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Serve accepts connections from ln until ctx is done or ln is closed.
func (s *Server) Serve(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // connection closed or context done
		}
		go s.handleStream(stream)
	}
}

// streamRW is the read/write surface handleStream needs — satisfied by
// *quic.Stream; narrowed for testability without a real QUIC connection.
type streamRW interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

func (s *Server) handleStream(stream streamRW) {
	defer stream.Close()

	raw, err := readFrame(stream)
	if err != nil {
		if errors.Is(err, ErrFrameTooLarge) {
			s.logf("quictrans: oversized frame, dropping stream: %v", err)
		}
		return
	}

	result := s.Gate.Accept(raw)

	var id string
	if result.Envelope != nil {
		id = result.Envelope.ID
	}
	status := StatusFrame{ID: id, Status: result.Status, Error: result.Err}

	buf, err := json.Marshal(status)
	if err != nil {
		s.logf("quictrans: marshal status frame: %v", err)
		return
	}
	if err := writeFrame(stream, buf); err != nil {
		s.logf("quictrans: write status frame: %v", err)
	}
}
