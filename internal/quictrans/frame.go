// Package quictrans implements the `awp/1` QUIC transport binding of
// spec/awp-quic-v0.1.md: envelope delivery only, optional, with mandatory
// HTTPS fallback and gate equivalence.
package quictrans

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/agentask/awp/internal/apperr"
)

// MaxFrameSize is the core §2.1 envelope cap, reused verbatim for QUIC
// frames (awp-quic §3).
const MaxFrameSize = 256 * 1024

// ErrFrameTooLarge is returned when a frame's declared length exceeds
// MaxFrameSize — awp-quic §3: "oversized frames are a connection error."
var ErrFrameTooLarge = errors.New("quictrans: frame exceeds 256 KiB limit")

// StatusFrame is the receiver->sender frame (awp-quic §3):
// {"id": "envelope-ulid", "status": 202, "error": null}. Status reuses the
// HTTPS gate codes verbatim (400/410/401/200/202/503).
type StatusFrame struct {
	ID     string        `json:"id"`
	Status int           `json:"status"`
	Error  *apperr.Error `json:"error"`
}

// writeFrame writes a 4-byte big-endian length prefix followed by payload.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("quictrans: write frame length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("quictrans: write frame payload: %w", err)
	}
	return nil
}

// readFrame reads one length-prefixed frame. A declared length over
// MaxFrameSize returns ErrFrameTooLarge without attempting to read the
// (potentially huge) payload — callers MUST treat this as a connection
// error (awp-quic §3), not merely a stream error.
func readFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("quictrans: read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("quictrans: read frame payload: %w", err)
	}
	return payload, nil
}
