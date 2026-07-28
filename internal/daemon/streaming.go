package daemon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/envelope"
)

// streamChunkProbe extracts just enough of an envelope body to decide
// whether it's a stream_chunk (awp-streaming-v0.1.md §2) without
// committing to that body shape — most envelope bodies are one of core
// §2.3's other types and this unmarshal is expected to leave Type empty
// or something else, which is not an error.
type streamChunkProbe struct {
	Type string `json:"type"`
}

// streamChunkBody is awp-streaming-v0.1.md §2's full shape, unmarshaled
// once streamChunkProbe has confirmed Type == "stream_chunk".
type streamChunkBody struct {
	Type     string          `json:"type"`
	StreamID string          `json:"stream_id"`
	Seq      *int            `json:"seq"`
	Final    bool            `json:"final"`
	Data     json.RawMessage `json:"data"`
}

// tryProcessStreamChunk inspects env's body for awp-streaming-v0.1.md's
// stream_chunk type, regardless of env.Kind (chunks typically carry
// kind: reply, per §2, but nothing here assumes that). handled=true
// means the envelope was a stream_chunk and has been fully dealt with —
// buffered/reassembled/delivered, or rejected with an error envelope
// back to the sender — and processOne must not fall through to its
// normal kind-based dispatch (no auto-ack/reply, no MessageHandler
// invocation for a chunk). handled=false means this wasn't a
// stream_chunk body at all; processOne continues as it always has.
func (d *Daemon) tryProcessStreamChunk(ctx context.Context, env *envelope.Envelope) (handled bool, err error) {
	var probe streamChunkProbe
	if err := json.Unmarshal(env.Body, &probe); err != nil || probe.Type != "stream_chunk" {
		return false, nil
	}

	if d.DisableStreaming {
		// core §2.3: "Unknown body types MUST produce an error envelope
		// (code: unsupported_body) — never a silent drop." This daemon
		// hasn't adopted awp-streaming-v0.1.md in this configuration, so
		// stream_chunk is exactly such an unknown type (awp-streaming
		// §9).
		return true, d.sendEnvelopeError(env, apperr.CodeUnsupportedBody,
			"stream_chunk (awp-streaming-v0.1.md) is not adopted by this implementation")
	}

	var chunk streamChunkBody
	if err := json.Unmarshal(env.Body, &chunk); err != nil || chunk.StreamID == "" || chunk.Seq == nil || *chunk.Seq < 0 {
		return true, d.sendEnvelopeError(env, apperr.CodeRefused,
			"malformed stream_chunk body: stream_id and a non-negative integer seq are required (awp-streaming-v0.1.md §2)")
	}

	outcome, err := d.Store.IngestStreamChunk(env.Thread, chunk.StreamID, *chunk.Seq, chunk.Final, chunk.Data, d.Clock.Now())
	if err != nil {
		return true, fmt.Errorf("daemon: ingest stream chunk %s/%s seq %d: %w", env.Thread, chunk.StreamID, *chunk.Seq, err)
	}
	if outcome.BoundExceeded {
		// awp-streaming-v0.1.md §6: "MUST be rejected with error(refused)
		// ... and the receiver MUST discard its reassembly buffer" — the
		// discard already happened inside IngestStreamChunk; this is just
		// the wire-visible half of that requirement.
		return true, d.sendEnvelopeError(env, apperr.CodeRefused,
			"stream exceeds the buffered-chunk bound (awp-streaming-v0.1.md §6); reassembly buffer discarded")
	}
	if outcome.Duplicate || len(outcome.Deliverable) == 0 {
		return true, nil
	}

	if d.StreamChunkHandler != nil {
		for _, c := range outcome.Deliverable {
			if err := d.StreamChunkHandler(ctx, env.Thread, chunk.StreamID, c.Seq, c.Final, c.Data); err != nil {
				return true, fmt.Errorf("daemon: stream chunk handler (thread %s stream %s seq %d): %w", env.Thread, chunk.StreamID, c.Seq, err)
			}
		}
	}
	return true, nil
}

// sendEnvelopeError sends an `error` envelope back to env's sender, body
// shaped per core §2.4 ("body is data with {code, detail, retryable}").
func (d *Daemon) sendEnvelopeError(env *envelope.Envelope, code, detail string) error {
	body, err := json.Marshal(map[string]any{
		"type": "data", "schema": nil,
		"data": map[string]any{"code": code, "detail": detail, "retryable": false},
	})
	if err != nil {
		return fmt.Errorf("daemon: marshal error body: %w", err)
	}
	_, err = d.Send("error", env.From, env.Thread, &env.ID, body)
	return err
}
