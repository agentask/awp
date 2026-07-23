package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

type checkMeta struct {
	id, desc string
}

// remainingCoreChecks lists every core §5 check besides 5.1 (the index
// check, which always runs first and gates everything else).
func remainingCoreChecks() []checkMeta {
	return []checkMeta{
		{"core-5.2-malformed", "Gate order: malformed envelope -> 400."},
		{"core-5.2-ttl-bounds", "Gate order: ttl outside [60, 604800] -> 400."},
		{"core-5.2-expired", "Gate order: expired envelope -> 410 (also core §5.6: never processes expired envelopes)."},
		{"core-5.2-unknown-signer", "Gate order: envelope signed by an unregistered key -> 401."},
		{"core-5.2-accept-and-dedupe", "Gate order: valid envelope -> 202, byte-identical resend -> 200 (deduped, not reprocessed)."},
		{"core-5.3-retention", "Retains seen-ids >= max accepted TTL."},
		{"core-5.4-delegation", "Verifies delegation per core §2.5 before acting on delegated envelopes."},
		{"core-5.5-unknown-body-type", "Emits error envelopes for unknown body types."},
		{"core-5.7-two-party", "Enforces the two-party thread invariant."},
	}
}

func postEnvelope(ctx context.Context, opts Options, inboxURL string, raw []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inboxURL, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/awp+json")
	resp, err := opts.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, nil
}

func runCoreChecks(ctx context.Context, domain string, idx *identity.Index, opts Options) []CheckResult {
	if idx.Inbox == "" {
		var results []CheckResult
		for _, c := range remainingCoreChecks() {
			results = append(results, CheckResult{ID: c.id, Description: c.desc, Status: Fail, Detail: "index declares no inbox URL"})
		}
		return results
	}

	var results []CheckResult
	results = append(results, checkMalformed(ctx, idx, opts))
	results = append(results, checkTTLBounds(ctx, domain, idx, opts))
	results = append(results, checkExpired(ctx, domain, idx, opts))
	results = append(results, checkUnknownSigner(ctx, domain, idx, opts))
	results = append(results, checkAcceptAndDedupe(ctx, domain, idx, opts))
	results = append(results, checkRetention())

	skipReason := "requires observing the target's async processing outcome (an error/reply envelope delivered back to the caller's own inbox); a stateless wire-level probe cannot verify this without also running a reachable receiving inbox, which is beyond this CLI's scope for an arbitrary target"
	results = append(results,
		CheckResult{ID: "core-5.4-delegation", Description: remainingCoreChecks()[6].desc, Status: Skip, Detail: skipReason},
		CheckResult{ID: "core-5.5-unknown-body-type", Description: remainingCoreChecks()[7].desc, Status: Skip, Detail: skipReason},
		CheckResult{ID: "core-5.7-two-party", Description: remainingCoreChecks()[8].desc, Status: Skip, Detail: "an internal store invariant, not observable via the wire protocol from outside"},
	)
	return results
}

func checkMalformed(ctx context.Context, idx *identity.Index, opts Options) CheckResult {
	meta := remainingCoreChecks()[0]
	status, err := postEnvelope(ctx, opts, idx.Inbox, []byte(`{not valid json`))
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status != 400 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("got %d, want 400", status)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

func checkTTLBounds(ctx context.Context, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingCoreChecks()[1]
	fromDomain, kid, sign := ephemeralSigner()
	raw, _, err := buildEnvelope(fromDomain+"#"+kid, domain, opts.now(), 1 /* below MinTTL */, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status != 400 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("got %d, want 400", status)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

func checkExpired(ctx context.Context, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingCoreChecks()[2]
	fromDomain, _, sign := ephemeralSigner()
	raw, _, err := buildEnvelope(fromDomain, domain, opts.now().Add(-2*time.Hour), 3600, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status != 410 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("got %d, want 410", status)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

func checkUnknownSigner(ctx context.Context, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingCoreChecks()[3]
	fromDomain, _, sign := ephemeralSigner()
	raw, _, err := buildEnvelope(fromDomain, domain, opts.now(), 3600, sign)
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

func checkAcceptAndDedupe(ctx context.Context, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingCoreChecks()[4]
	if opts.CallerPriv == nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Skip, Detail: "requires --key/--kid for an identity the target's own index already trusts (a domain testing itself supplies its own key)"}
	}
	raw, env, err := buildEnvelope(opts.CallerDomain, domain, opts.now(), 3600, func(e *envelope.Envelope) error {
		return e.Sign(opts.CallerPriv, opts.CallerKid)
	})
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status1, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status1 != 202 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("first delivery: got %d, want 202 (id=%s)", status1, env.ID)}
	}
	status2, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status2 != 200 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("resend: got %d, want 200 (deduped)", status2)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

// checkRetention is unconditionally Skip.
//
// This was originally implemented as a real probe (sleep out a full
// minimum TTL, then resend the same now-expired envelope and expect a
// dedupe 200) before discovering, by actually running it, that the
// property it wants to observe is masked by core §2.2's own gate order:
// gate 2 (TTL check) runs BEFORE gate 4 (dedupe), so ANY resend of an
// envelope past its own ts+ttl gets 410 regardless of whether the receiver
// retained the seen-id or garbage-collected it early — the two cases are
// indistinguishable from outside. Retention only matters for resends that
// arrive WHILE the envelope is still valid, which is exactly what
// core-5.2-accept-and-dedupe already exercises. There is no additional
// externally observable signal a black-box wire-level probe can extract
// for this specific checklist item; keeping the check (rather than
// deleting it) preserves the mapping to core §5's checklist numbering and
// records why it can't be more than Skip.
func checkRetention() CheckResult {
	meta := remainingCoreChecks()[5]
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Skip,
		Detail: "not externally observable: core §2.2 gate order runs the TTL check before the dedupe check, so any resend past an envelope's own ttl gets 410 regardless of seen-id retention — see checkRetention's doc comment"}
}
