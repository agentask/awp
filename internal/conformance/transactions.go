package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/agentask/awp/internal/httpsig"
	"github.com/agentask/awp/internal/identity"
)

// checkMalformedTransactionRejected covers awp-transactions-v0.1.md §5.2:
// a present-but-malformed AWP-Transaction header MUST be rejected with a
// malformed error, unlike AWP-Dry-Run's single boolean (which has no
// invalid non-empty state). Any callable kind:tool entity is a valid
// probe target — the header is handled uniformly by every sync-call
// endpoint, regardless of whether that entity's manifest even mentions
// transactions.
func checkMalformedTransactionRejected(ctx context.Context, opts Options, idx *identity.Index) CheckResult {
	const id = "awp-transactions-5.2-malformed-header-rejected"
	const desc = "A sync call carrying a malformed AWP-Transaction header is rejected with a malformed error (awp-transactions-v0.1.md §2/§5)."

	if opts.CallerPriv == nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "requires -key/-kid to sign a sync call"}
	}

	principal, endpoint, err := findHostedEntity(ctx, opts, idx, "tool")
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "could not resolve a callable tool to probe: " + err.Error()}
	}
	if endpoint == "" {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "domain publishes no kind:tool entity with a hosted endpoint to probe"}
	}

	body := []byte(`{}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	req.Header.Set("AWP-Transaction", "not-valid-base64url-json!!!")
	keyID := opts.CallerDomain + "/" + opts.CallerKid
	if err := httpsig.Sign(req, body, opts.CallerPriv, keyID, opts.now()); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "sign probe request: " + err.Error()}
	}

	resp, err := opts.client().Do(req)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: err.Error()}
	}
	if resp.StatusCode != http.StatusBadRequest {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fmt.Sprintf("%s: status %d, want 400: %s", principal, resp.StatusCode, respBody)}
	}
	return CheckResult{ID: id, Description: desc, Status: Pass, Detail: fmt.Sprintf("%s correctly rejected a malformed AWP-Transaction header with 400", principal)}
}

// checkCompensatedByResolvable covers awp-transactions-v0.1.md §5.3: the
// only externally-checkable claim about a declared compensated_by
// principal is that it resolves to a real, callable entity — whether it
// actually undoes anything is unobservable from outside, exactly like
// AWP-Dry-Run's no-side-effect claim (awp-capabilities-v0.1.md §4.2).
// Only same-domain compensated_by targets are checked; a cross-domain
// target Skips rather than fetching a second domain's index, matching
// this package's indexKeyResolver's same-domain scope elsewhere.
func checkCompensatedByResolvable(ctx context.Context, opts Options, idx *identity.Index) CheckResult {
	const id = "awp-transactions-5.3-compensated-by-resolvable"
	const desc = "A declared compensated_by principal, if same-domain, resolves to a real, callable entity (awp-transactions-v0.1.md §1/§5)."

	compensatedBy, declaredBy, err := findCompensatedBy(ctx, opts, idx)
	if err != nil {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "could not search entities for a compensated_by declaration: " + err.Error()}
	}
	if compensatedBy == "" {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: "domain declares no compensated_by on any entity"}
	}
	if identity.DomainOf(compensatedBy) != idx.Domain {
		return CheckResult{ID: id, Description: desc, Status: Skip, Detail: fmt.Sprintf("%s declares compensated_by=%s, a cross-domain target this checklist item does not follow", declaredBy, compensatedBy)}
	}

	for _, entry := range idx.Entities {
		if entry.Name != compensatedBy {
			continue
		}
		if _, ferr := fetchAndVerifyManifest(ctx, opts, idx, entry.Manifest, entry.ManifestSha256); ferr != nil {
			return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fmt.Sprintf("%s's compensated_by target %s failed manifest fetch/verify: %v", declaredBy, compensatedBy, ferr)}
		}
		return CheckResult{ID: id, Description: desc, Status: Pass, Detail: fmt.Sprintf("%s's compensated_by target %s resolved and verified", declaredBy, compensatedBy)}
	}
	return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fmt.Sprintf("%s declares compensated_by=%s, which is not listed in this domain's own index entities", declaredBy, compensatedBy)}
}

// findCompensatedBy returns the first entity whose manifest declares a
// non-empty CompensatedBy, along with that entity's own principal. ("",
// "", nil) means none was found.
func findCompensatedBy(ctx context.Context, opts Options, idx *identity.Index) (compensatedBy, declaredBy string, err error) {
	for _, entry := range idx.Entities {
		m, ferr := fetchAndVerifyManifest(ctx, opts, idx, entry.Manifest, entry.ManifestSha256)
		if ferr != nil {
			continue // one broken entity shouldn't sink the check
		}
		if m.CompensatedBy != "" {
			return m.CompensatedBy, entry.Name, nil
		}
	}
	return "", "", nil
}
