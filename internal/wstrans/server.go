package wstrans

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/agentask/awp/internal/inbox"
)

// Server accepts awp-ws/1 connections and runs every envelope message
// through the SAME inbox.Gate an HTTPS listener would use —
// awp-ws-v0.1.md §5 rule 1 (gate equivalence) holds by construction:
// there is only one Gate.Accept, called from every transport adapter
// (HTTP, awp/1, and this one).
type Server struct {
	Gate *inbox.Gate
	// Logf receives non-fatal per-connection errors (a peer disconnecting
	// mid-connection is normal, not a bug). Defaults to discarding.
	Logf func(format string, args ...any)
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// ServeHTTP is an http.HandlerFunc-compatible method: mount it at this
// daemon's awp-ws/1 path (awp-ws-v0.1.md §1/§2) on the SAME mux that
// serves the rest of the daemon's HTTPS surface — this binding needs no
// separate listener, unlike internal/quictrans.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrade(w, r)
	if err != nil {
		http.Error(w, "websocket upgrade failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	go s.handleConn(conn)
}

// handleConn reads envelope messages off conn until it errors or the
// peer closes it. Each message's gate call runs in its own goroutine
// (awp-ws-v0.1.md §7 conformance item 4: "≥ 100 concurrent envelopes
// multiplexed on one connection," not merely ≥ 100 concurrent
// connections) — reads stay strictly serialized (one connection, one
// reader), but a slow tool/gate call never blocks reading the next
// message. writeMu serializes the resulting status-frame writes, since
// concurrent unsynchronized writers on one connection would interleave
// frame bytes.
func (s *Server) handleConn(conn *Conn) {
	defer conn.Close()
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		_, payload, err := readFrame(conn)
		if err != nil {
			return // Close/ping/pong/reserved/transport error: nothing more to read
		}

		wg.Add(1)
		go func(payload []byte) {
			defer wg.Done()
			result := s.Gate.Accept(payload)

			var id string
			if result.Envelope != nil {
				id = result.Envelope.ID
			}
			buf, err := json.Marshal(StatusFrame{ID: id, Status: result.Status, Error: result.Err})
			if err != nil {
				s.logf("wstrans: marshal status frame: %v", err)
				return
			}

			writeMu.Lock()
			defer writeMu.Unlock()
			if err := writeFrame(conn, opcodeBinary, buf, false); err != nil {
				s.logf("wstrans: write status frame: %v", err)
			}
		}(payload)
	}
}
