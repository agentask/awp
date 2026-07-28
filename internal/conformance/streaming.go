package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

// remainingStreamingChecks lists the awp-streaming-v0.1.md §10 checklist.
func remainingStreamingChecks() []checkMeta {
	return []checkMeta{
		{"awp-streaming-1-capability-advertised", "Whether the domain advertises the \"awp-streaming-v0.1\" capability (informational — absence is not itself non-conformant, awp-capabilities-v0.1.md §1)."},
		{"awp-streaming-10.1-signature-verified-before-buffering", "A stream_chunk envelope from an unregistered signer is rejected at the gate (401), exactly like any other envelope — no bypass for stream_chunk bodies specifically."},
		{"awp-streaming-10.2-out-of-order-reassembly", "Out-of-order chunk delivery is tolerated and correctly reassembled by seq."},
		{"awp-streaming-10.3-no-gap-delivery", "A stream is not delivered to the application layer with a gap in seq."},
		{"awp-streaming-10.4-bound-enforced", "The §6 65536-chunk buffered bound is enforced, and exceeding it produces error(refused)."},
		{"awp-streaming-10.5-non-adopting-rejects", "An implementation that has not adopted this document rejects a stream_chunk body with error(unsupported_body)."},
	}
}

// runStreamingChecks implements the awp-streaming-v0.1.md §10 checklist,
// outside the core §5 / awp-quic §8 checklists this package otherwise
// implements — like checkStatusEntity and checkWakeEndpointReachable,
// this is a registered extension, not a core checklist item.
func runStreamingChecks(ctx context.Context, domain string, idx *identity.Index, opts Options) []CheckResult {
	meta := remainingStreamingChecks()
	results := []CheckResult{checkStreamingCapabilityAdvertised(idx, meta[0])}

	if idx.Inbox == "" {
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Skip, Detail: "index declares no inbox URL"})
		}
		return results
	}

	results = append(results, checkStreamingSignatureVerifiedFirst(ctx, domain, idx, opts, meta[1]))

	// §10 items 2-4 all require observing this domain's own internal
	// reassembly state (what it delivered to its application layer, or
	// whether it discarded a buffer) — none of that is wire-visible to a
	// stateless prober, exactly like core-5.7-two-party and
	// core-5.4-delegation/core-5.5-unknown-body-type already document for
	// this same package (see core5.go's runCoreChecks). Verified instead
	// by the reference implementation's own test suite
	// (internal/store/streams_test.go, internal/daemon/streaming_test.go).
	internalStateReason := "requires observing the target's own internal reassembly state (what was delivered to its application layer, or whether a buffer was discarded) — a stateless wire-level probe cannot verify this, exactly like core-5.7-two-party; verified instead by the reference implementation's own test suite (internal/store, internal/daemon)"
	results = append(results,
		CheckResult{ID: meta[2].id, Description: meta[2].desc, Status: Skip, Detail: internalStateReason},
		CheckResult{ID: meta[3].id, Description: meta[3].desc, Status: Skip, Detail: internalStateReason},
		CheckResult{ID: meta[4].id, Description: meta[4].desc, Status: Skip, Detail: internalStateReason},
	)

	// §10 item 5's rejection is delivered as a SEPARATE async error
	// envelope back to the sender's own inbox (awp-streaming-v0.1.md §2
	// carries no synchronous rejection channel) — the identical
	// observability limit core-5.5-unknown-body-type already documents.
	results = append(results, CheckResult{
		ID: meta[5].id, Description: meta[5].desc, Status: Skip,
		Detail: "requires observing the target's async processing outcome (an error envelope delivered back to the caller's own inbox); a stateless wire-level probe cannot verify this without also running a reachable receiving inbox, which is beyond this CLI's scope for an arbitrary target — identical to core-5.5-unknown-body-type's own limitation",
	})
	return results
}

func checkStreamingCapabilityAdvertised(idx *identity.Index, meta checkMeta) CheckResult {
	if slices.Contains(idx.Capabilities, "awp-streaming-v0.1") {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass, Detail: "advertises \"awp-streaming-v0.1\""}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass, Detail: "does not advertise \"awp-streaming-v0.1\" — absence is not itself non-conformant"}
}

// checkStreamingSignatureVerifiedFirst covers §10 item 1: a stream_chunk
// envelope is rejected by the SAME gate, on the SAME grounds (here: an
// unregistered signer), as any other envelope — proving there is no
// special-cased bypass that lets a stream_chunk body's content reach the
// reassembly buffer (or anything else) before its signature is checked.
func checkStreamingSignatureVerifiedFirst(ctx context.Context, domain string, idx *identity.Index, opts Options, meta checkMeta) CheckResult {
	fromDomain, _, sign := ephemeralSigner()
	body, err := json.Marshal(map[string]any{
		"type": "stream_chunk", "stream_id": envelope.NewID(), "seq": 0, "final": true,
		"data": map[string]string{"text": "conformance probe"},
	})
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	raw, _, err := buildStreamChunkEnvelope(fromDomain, domain, opts.now(), 3600, body, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status != 401 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("got %d, want 401", status)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

// buildStreamChunkEnvelope mirrors this package's own buildEnvelope, with
// a caller-supplied body instead of a fixed text body — needed since
// awp-streaming-v0.1.md chunks typically carry kind: reply, and always
// carry a stream_chunk body, neither of which buildEnvelope's fixed
// message/text shape offers.
func buildStreamChunkEnvelope(from, to string, ts time.Time, ttl int, body json.RawMessage, sign func(*envelope.Envelope) error) ([]byte, *envelope.Envelope, error) {
	e := &envelope.Envelope{
		Awp: "0.1", ID: envelope.NewID(), Kind: "reply",
		From: from, To: to, Thread: envelope.NewID(),
		Ts: ts.UTC().Format("2006-01-02T15:04:05.000Z"), TTL: ttl,
		Body: body,
	}
	if err := sign(e); err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(e)
	return raw, e, err
}
