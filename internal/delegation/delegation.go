// Package delegation implements chain verification for AWP delegation
// proofs per core §2.5.
package delegation

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/agentask/awp/internal/identity"
)

// MaxChainLength is core §2.5 rule 6.
const MaxChainLength = 8

// Scope restricts what a delegate may do on the delegator's behalf.
// Absent fields mean unrestricted for that field (core §2.5).
type Scope struct {
	To        *string  `json:"to,omitempty"`
	Kinds     []string `json:"kinds,omitempty"`
	BodyTypes []string `json:"body_types,omitempty"`
}

func (s Scope) isEntirelyUnscopedTo() bool {
	return s.To == nil
}

// Link is one entry of a delegation chain (core §2.5).
type Link struct {
	Delegator string        `json:"delegator"`
	Delegate  string        `json:"delegate"`
	Scope     Scope         `json:"scope"`
	Expires   string        `json:"expires"`
	Nonce     string        `json:"nonce"`
	Sig       *identity.Sig `json:"sig,omitempty"`
}

// Sign attaches l.Sig per core §0.1, signed by the delegator's domain key.
func (l *Link) Sign(priv ed25519.PrivateKey, kid string) error {
	sig, err := identity.Sign(l, priv, kid)
	if err != nil {
		return err
	}
	l.Sig = sig
	return nil
}

// Rule names identify which core §2.5 validity rule failed.
const (
	RuleChainTooLong       = "chain_too_long"       // rule 6
	RuleRootScopeUnbounded = "root_scope_unbounded" // rule 5 (root-link special case)
	RuleBadSignature       = "signature"            // rule 1
	RuleExpired            = "expiry"               // rule 3
	RuleContinuity         = "continuity"           // rule 2
	RuleFinalDelegate      = "final_delegate"       // rule 4
	RuleScopeIntersection  = "scope_intersection"   // rule 5
)

// RuleViolation identifies exactly which core §2.5 rule rejected a chain,
// and at which link (-1 when not link-specific).
type RuleViolation struct {
	Rule      string
	LinkIndex int
	Detail    string
}

func (e *RuleViolation) Error() string {
	if e.LinkIndex < 0 {
		return fmt.Sprintf("delegation: rule %q violated: %s", e.Rule, e.Detail)
	}
	return fmt.Sprintf("delegation: rule %q violated at link %d: %s", e.Rule, e.LinkIndex, e.Detail)
}

// KeyResolver resolves a domain+kid to the domain's currently trusted
// public key (via that domain's index, out of scope for this package).
type KeyResolver func(domain, kid string) (ed25519.PublicKey, error)

// VerifyInput bundles the envelope (or sync-call) context a chain is
// checked against.
type VerifyInput struct {
	Chain      []Link
	From       string // final signing principal (envelope `from`, or sync keyid principal)
	To         string
	Kind       string
	BodyType   string
	Now        time.Time
	ResolveKey KeyResolver
}

// Verify runs every core §2.5 validity rule against the chain, short-
// circuiting on the first violation and identifying it specifically. An
// empty chain is not itself a violation — it means no delegation is being
// asserted; callers only invoke Verify when the envelope claims delegated
// authority.
func Verify(in VerifyInput) error {
	if len(in.Chain) == 0 {
		return nil
	}
	if len(in.Chain) > MaxChainLength {
		return &RuleViolation{Rule: RuleChainTooLong, LinkIndex: -1,
			Detail: fmt.Sprintf("chain has %d links, max %d", len(in.Chain), MaxChainLength)}
	}

	if err := verifyRootScopeBound(in.Chain[0]); err != nil {
		return err
	}

	for i, link := range in.Chain {
		if err := verifyLinkSignature(in.ResolveKey, link, i); err != nil {
			return err
		}
		if err := verifyLinkUnexpired(link, in.Now, i); err != nil {
			return err
		}
		if i > 0 {
			if in.Chain[i-1].Delegate != link.Delegator {
				return &RuleViolation{Rule: RuleContinuity, LinkIndex: i,
					Detail: fmt.Sprintf("link %d delegate %q != link %d delegator %q",
						i-1, in.Chain[i-1].Delegate, i, link.Delegator)}
			}
		}
	}

	last := in.Chain[len(in.Chain)-1]
	if last.Delegate != in.From {
		return &RuleViolation{Rule: RuleFinalDelegate, LinkIndex: len(in.Chain) - 1,
			Detail: fmt.Sprintf("final delegate %q != envelope from %q", last.Delegate, in.From)}
	}

	if err := verifyScopeIntersection(in.Chain, in.To, in.Kind, in.BodyType); err != nil {
		return err
	}

	return nil
}

// verifyRootScopeBound enforces core §2.5 rule 5's root-link special case:
// an entirely empty root scope is invalid — root links MUST either scope
// `to` or carry expires <= 24h. Root link duration is measured from the
// link's nonce (a ULID, which embeds its own creation time) to its expiry.
func verifyRootScopeBound(root Link) error {
	if !root.Scope.isEntirelyUnscopedTo() {
		return nil
	}
	nonceTime, err := decodeULIDTime(root.Nonce)
	if err != nil {
		return &RuleViolation{Rule: RuleRootScopeUnbounded, LinkIndex: 0,
			Detail: "root link has no `to` scope and nonce is not a valid ULID: " + err.Error()}
	}
	expiresTime, err := time.Parse(time.RFC3339, root.Expires)
	if err != nil {
		return &RuleViolation{Rule: RuleRootScopeUnbounded, LinkIndex: 0,
			Detail: "root link has no `to` scope and expires is not valid RFC3339: " + err.Error()}
	}
	if expiresTime.Sub(nonceTime) > 24*time.Hour {
		return &RuleViolation{Rule: RuleRootScopeUnbounded, LinkIndex: 0,
			Detail: "root link has no `to` scope and expires > 24h after issuance"}
	}
	return nil
}

func decodeULIDTime(nonce string) (time.Time, error) {
	id, err := ulid.ParseStrict(strings.ToUpper(nonce))
	if err != nil {
		return time.Time{}, err
	}
	return ulid.Time(id.Time()), nil
}

func verifyLinkSignature(resolve KeyResolver, link Link, index int) error {
	if link.Sig == nil {
		return &RuleViolation{Rule: RuleBadSignature, LinkIndex: index, Detail: "missing sig"}
	}
	pub, err := resolve(identity.DomainOf(link.Delegator), link.Sig.Kid)
	if err != nil {
		return &RuleViolation{Rule: RuleBadSignature, LinkIndex: index,
			Detail: "resolve delegator key: " + err.Error()}
	}
	if err := identity.VerifySig(link, link.Sig, pub); err != nil {
		return &RuleViolation{Rule: RuleBadSignature, LinkIndex: index, Detail: err.Error()}
	}
	return nil
}

func verifyLinkUnexpired(link Link, now time.Time, index int) error {
	expiresTime, err := time.Parse(time.RFC3339, link.Expires)
	if err != nil {
		return &RuleViolation{Rule: RuleExpired, LinkIndex: index,
			Detail: "expires is not valid RFC3339: " + err.Error()}
	}
	if now.After(expiresTime) {
		return &RuleViolation{Rule: RuleExpired, LinkIndex: index, Detail: "link expired"}
	}
	return nil
}

func verifyScopeIntersection(chain []Link, to, kind, bodyType string) error {
	for i, link := range chain {
		if link.Scope.To != nil && *link.Scope.To != to {
			return &RuleViolation{Rule: RuleScopeIntersection, LinkIndex: i,
				Detail: fmt.Sprintf("scope.to %q excludes envelope to %q", *link.Scope.To, to)}
		}
		if len(link.Scope.Kinds) > 0 && !slices.Contains(link.Scope.Kinds, kind) {
			return &RuleViolation{Rule: RuleScopeIntersection, LinkIndex: i,
				Detail: fmt.Sprintf("scope.kinds %v excludes envelope kind %q", link.Scope.Kinds, kind)}
		}
		if len(link.Scope.BodyTypes) > 0 && !slices.Contains(link.Scope.BodyTypes, bodyType) {
			return &RuleViolation{Rule: RuleScopeIntersection, LinkIndex: i,
				Detail: fmt.Sprintf("scope.body_types %v excludes envelope body type %q", link.Scope.BodyTypes, bodyType)}
		}
	}
	return nil
}
