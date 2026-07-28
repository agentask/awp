// Package wstrans implements the `awp-ws/1` WebSocket transport binding
// of spec/awp-ws-v0.1.md: envelope delivery only, optional, with
// mandatory fallback and gate equivalence — the same scope
// internal/quictrans has for `awp/1`, over a connection any HTTPS
// deployment already accepts.
//
// This package hand-rolls RFC 6455 framing and the handshake rather than
// pulling a WebSocket library, in the same spirit CLAUDE.md documents for
// RFC 9421 ("minimal in-house subset... do NOT pull a library"): AWP's
// own use of WebSocket needs exactly one thing from the protocol — a
// reusable, ordered, bidirectional byte-message channel between two AWP
// daemons we both control — not the full surface (fragmentation,
// ping/pong, extensions, subprotocols) a browser-facing implementation
// would need. §4 of the spec documents each simplification explicitly.
package wstrans

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/agentask/awp/internal/apperr"
)

// MaxFrameSize is the core §2.1 envelope cap, reused verbatim for
// WebSocket frames (awp-ws-v0.1.md §3), exactly as internal/quictrans
// does for `awp/1`.
const MaxFrameSize = 256 * 1024

// ErrFrameTooLarge is returned when a frame's declared length exceeds
// MaxFrameSize — awp-ws-v0.1.md §3: a connection error, not a stream-
// level one (there are no independent streams on this transport).
var ErrFrameTooLarge = errors.New("wstrans: frame exceeds 256 KiB limit")

// ErrFragmentedFrame is returned for a frame with FIN=0 — v0.1 does not
// support fragmentation (awp-ws-v0.1.md §4): every envelope or status
// message MUST fit in one frame, well within the 256 KiB cap.
var ErrFragmentedFrame = errors.New("wstrans: fragmented frames are not supported in v0.1")

// ErrUnsupportedOpcode is returned for any opcode this binding doesn't
// use — ping/pong (0x9/0xA) and any reserved opcode. awp-ws-v0.1.md §4
// explicitly puts ping/pong keepalive out of scope for v0.1.
var ErrUnsupportedOpcode = errors.New("wstrans: unsupported WebSocket opcode")

// ErrConnectionClosed is returned by readFrame when the peer sent a
// Close frame (opcode 0x8) — a clean shutdown, not a transport error.
var ErrConnectionClosed = errors.New("wstrans: peer closed the connection")

const (
	opcodeText   = 0x1
	opcodeBinary = 0x2
	opcodeClose  = 0x8
	opcodePing   = 0x9
	opcodePong   = 0xA
)

// StatusFrame is the receiver->sender message (awp-ws-v0.1.md §3):
// {"id": "envelope-ulid", "status": 202, "error": null}. Status reuses
// the HTTPS gate codes verbatim, identically to internal/quictrans's own
// StatusFrame — a separate type per package, by design (§0 of this
// package's doc comment: independent transport bindings, not a shared
// dependency).
type StatusFrame struct {
	ID     string        `json:"id"`
	Status int           `json:"status"`
	Error  *apperr.Error `json:"error"`
}

// writeFrame writes one RFC 6455 §5.2 frame: FIN=1, the given opcode, and
// payload. masked selects client-to-server framing (RFC 6455 §5.3
// requires client frames to be masked; server frames MUST NOT be) — the
// masking key is freshly random per frame.
func writeFrame(w io.Writer, opcode byte, payload []byte, masked bool) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	var header []byte
	header = append(header, 0x80|opcode) // FIN=1, RSV=0, opcode

	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, maskBit|byte(n))
	case n <= 0xFFFF:
		header = append(header, maskBit|126)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		header = append(header, lenBuf[:]...)
	default:
		header = append(header, maskBit|127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(n))
		header = append(header, lenBuf[:]...)
	}

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("wstrans: write frame header: %w", err)
	}

	if !masked {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("wstrans: write frame payload: %w", err)
		}
		return nil
	}

	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return fmt.Errorf("wstrans: generate mask key: %w", err)
	}
	if _, err := w.Write(maskKey[:]); err != nil {
		return fmt.Errorf("wstrans: write mask key: %w", err)
	}
	maskedPayload := make([]byte, n)
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}
	if _, err := w.Write(maskedPayload); err != nil {
		return fmt.Errorf("wstrans: write masked payload: %w", err)
	}
	return nil
}

// readFrame reads one RFC 6455 §5.2 frame and returns its opcode and
// (unmasked, if it was masked) payload. A control frame this binding
// doesn't support (ping/pong, any reserved opcode) returns
// ErrUnsupportedOpcode; a Close frame returns ErrConnectionClosed with
// opcodeClose and no payload guarantee; a fragmented frame (FIN=0)
// returns ErrFragmentedFrame — all three are connection-ending errors
// callers must not retry on this same connection.
func readFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, fmt.Errorf("wstrans: read frame header: %w", err)
	}
	fin := head[0]&0x80 != 0
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length7 := head[1] & 0x7F

	if !fin {
		return opcode, nil, ErrFragmentedFrame
	}

	var length uint64
	switch length7 {
	case 126:
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, nil, fmt.Errorf("wstrans: read extended length: %w", err)
		}
		length = uint64(binary.BigEndian.Uint16(lenBuf[:]))
	case 127:
		var lenBuf [8]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, nil, fmt.Errorf("wstrans: read extended length: %w", err)
		}
		length = binary.BigEndian.Uint64(lenBuf[:])
	default:
		length = uint64(length7)
	}
	if length > MaxFrameSize {
		return opcode, nil, ErrFrameTooLarge
	}

	if masked {
		var maskKey [4]byte
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, fmt.Errorf("wstrans: read mask key: %w", err)
		}
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("wstrans: read frame payload: %w", err)
		}
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	} else {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, fmt.Errorf("wstrans: read frame payload: %w", err)
		}
	}

	switch opcode {
	case opcodeText, opcodeBinary:
		return opcode, payload, nil
	case opcodeClose:
		return opcode, payload, ErrConnectionClosed
	default: // opcodePing, opcodePong, reserved opcodes
		return opcode, payload, ErrUnsupportedOpcode
	}
}
