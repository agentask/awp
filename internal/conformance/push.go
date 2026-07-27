package conformance

import (
	"context"
	"fmt"
	"net/http"

	"github.com/agentask/awp/internal/identity"
)

// checkWakeEndpointReachable is, like checkStatusEntity, outside the core
// §5 / awp-quic §8 checklists — awp-push-v0.1.md §2 registers `wake` as an
// OPTIONAL index field, not a core checklist item. Skips (not fails) when
// the domain declares no wake endpoint at all.
//
// Per awp-push-v0.1.md §5 rule 2, this is a reachability smoke test only:
// it confirms an empty POST gets some HTTP response without hanging. It
// makes no claim about whether wake notifications actually cause anything
// to happen — that is unobservable from outside, exactly like
// awp-capabilities-v0.1.md §4's dry-run no-side-effect claim.
func checkWakeEndpointReachable(ctx context.Context, opts Options, idx *identity.Index) CheckResult {
	const id = "awp-push-2-wake-reachable"
	const desc = "A declared wake endpoint, if present, accepts an empty POST and responds without hanging (awp-push-v0.1.md §2)."

	if idx.Wake == nil || idx.Wake.Endpoint == "" {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "domain declares no wake endpoint"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idx.Wake.Endpoint, nil)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	defer resp.Body.Close()
	return CheckResult{ID: id, Description: desc, Status: Pass, Detail: fmt.Sprintf("%s: status %d", idx.Wake.Endpoint, resp.StatusCode)}
}
