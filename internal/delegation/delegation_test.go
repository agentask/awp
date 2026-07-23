package delegation

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/agentask/awp/internal/identity"
)

// testKeyring is a tiny in-memory (domain, kid) -> pubkey resolver standing
// in for a real domain-index fetch, which is out of scope for this package.
type testKeyring struct {
	keys map[string]ed25519.PublicKey
}

func newTestKeyring() *testKeyring {
	return &testKeyring{keys: map[string]ed25519.PublicKey{}}
}

func (r *testKeyring) add(domain, kid string) ed25519.PrivateKey {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	r.keys[domain+"/"+kid] = pub
	return priv
}

func (r *testKeyring) resolve(domain, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[domain+"/"+kid]
	if !ok {
		return nil, fmt.Errorf("no key for %s/%s", domain, kid)
	}
	return pub, nil
}

func nonceAt(t time.Time) string {
	return ulid.MustNew(ulid.Timestamp(t), nil).String()
}

func rfc3339(t time.Time) string {
	return t.Format(time.RFC3339)
}

// baseline builds a valid 2-link delegation chain:
//
//	user-root.example.com --[scope.to=example.com#generate-invoice]--> assistant.acme.com#scheduler
//	assistant.acme.com#scheduler --[unrestricted]--> assistant.acme.com#subagent
//
// against which envelope (From=assistant.acme.com#subagent, To=example.com#generate-invoice,
// Kind=message, BodyType=task) is valid. Returns the chain and a VerifyInput
// pre-populated with the matching envelope context; tests mutate copies to
// isolate exactly one rule violation.
func baseline(t *testing.T, now time.Time) ([]Link, VerifyInput, *testKeyring) {
	t.Helper()
	kr := newTestKeyring()
	rootPriv := kr.add("user-root.example.com", "k1")
	schedPriv := kr.add("assistant.acme.com", "k1")

	rootTarget := "example.com#generate-invoice"
	root := Link{
		Delegator: "user-root.example.com",
		Delegate:  "assistant.acme.com#scheduler",
		Scope:     Scope{To: &rootTarget},
		Expires:   rfc3339(now.Add(2 * time.Hour)),
		Nonce:     nonceAt(now),
	}
	if err := root.Sign(rootPriv, "k1"); err != nil {
		t.Fatalf("sign root: %v", err)
	}

	sub := Link{
		Delegator: "assistant.acme.com#scheduler",
		Delegate:  "assistant.acme.com#subagent",
		Scope:     Scope{},
		Expires:   rfc3339(now.Add(time.Hour)),
		Nonce:     nonceAt(now),
	}
	if err := sub.Sign(schedPriv, "k1"); err != nil {
		t.Fatalf("sign sub: %v", err)
	}

	chain := []Link{root, sub}
	in := VerifyInput{
		Chain:      chain,
		From:       "assistant.acme.com#subagent",
		To:         "example.com#generate-invoice",
		Kind:       "message",
		BodyType:   "task",
		Now:        now,
		ResolveKey: kr.resolve,
	}
	return chain, in, kr
}

func TestVerify_HappyPath(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	_, in, _ := baseline(t, now)
	if err := Verify(in); err != nil {
		t.Fatalf("expected valid chain, got: %v", err)
	}
}

func TestVerify_EmptyChainIsNotAViolation(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	in := VerifyInput{Chain: nil, From: "x.example.com", To: "y.example.com", Now: now}
	if err := Verify(in); err != nil {
		t.Fatalf("empty chain should not be a violation, got: %v", err)
	}
}

// EARS gate 3: each core §2.5 rule, violated in isolation, rejects with the
// specific rule identified.
func TestVerify_EachRuleViolatedInIsolation(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		mutate    func(chain []Link, in *VerifyInput, kr *testKeyring)
		wantRule  string
		wantIndex int
	}{
		{
			name: "chain exceeds 8 links",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				long := make([]Link, 9)
				for i := range long {
					long[i] = chain[0]
				}
				in.Chain = long
			},
			wantRule:  RuleChainTooLong,
			wantIndex: -1,
		},
		{
			name: "root scope unbounded: no `to`, expires > 24h",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				priv := kr.add("user-root.example.com", "k2")
				root := Link{
					Delegator: "user-root.example.com",
					Delegate:  "assistant.acme.com#scheduler",
					Scope:     Scope{}, // no `to`
					Expires:   rfc3339(now.Add(25 * time.Hour)),
					Nonce:     nonceAt(now),
				}
				if err := root.Sign(priv, "k2"); err != nil {
					t.Fatalf("sign: %v", err)
				}
				in.Chain = []Link{root, chain[1]}
			},
			wantRule:  RuleRootScopeUnbounded,
			wantIndex: 0,
		},
		{
			name: "bad signature on root link",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				tampered := chain[0]
				tampered.Delegate = "someone-else.example.com#x" // invalidates existing sig
				in.Chain = []Link{tampered, chain[1]}
				in.From = "assistant.acme.com#subagent" // unreachable; sig check comes first
			},
			wantRule:  RuleBadSignature,
			wantIndex: 0,
		},
		{
			name: "expired root link",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				priv := kr.add("user-root.example.com", "k3")
				target := "example.com#generate-invoice"
				root := Link{
					Delegator: "user-root.example.com",
					Delegate:  "assistant.acme.com#scheduler",
					Scope:     Scope{To: &target},
					Expires:   rfc3339(now.Add(-time.Hour)), // already expired
					Nonce:     nonceAt(now.Add(-2 * time.Hour)),
				}
				if err := root.Sign(priv, "k3"); err != nil {
					t.Fatalf("sign: %v", err)
				}
				in.Chain = []Link{root, chain[1]}
			},
			wantRule:  RuleExpired,
			wantIndex: 0,
		},
		{
			name: "continuity break between link 0 and link 1",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				priv := kr.add("someone-else.example.org", "k1")
				broken := Link{
					Delegator: "someone-else.example.org#not-the-delegate", // != root.Delegate
					Delegate:  "assistant.acme.com#subagent",
					Scope:     Scope{},
					Expires:   rfc3339(now.Add(time.Hour)),
					Nonce:     nonceAt(now),
				}
				if err := broken.Sign(priv, "k1"); err != nil {
					t.Fatalf("sign: %v", err)
				}
				in.Chain = []Link{chain[0], broken}
			},
			wantRule:  RuleContinuity,
			wantIndex: 1,
		},
		{
			name: "final delegate does not match envelope from",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				in.From = "someone-entirely-different.example.com#x"
			},
			wantRule:  RuleFinalDelegate,
			wantIndex: 1,
		},
		{
			name: "scope intersection: envelope `to` outside root scope",
			mutate: func(chain []Link, in *VerifyInput, kr *testKeyring) {
				in.To = "other.example.com#other-tool"
			},
			wantRule:  RuleScopeIntersection,
			wantIndex: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, in, kr := baseline(t, now)
			tt.mutate(chain, &in, kr)
			err := Verify(in)
			if err == nil {
				t.Fatalf("expected violation of rule %q, got nil", tt.wantRule)
			}
			rv, ok := err.(*RuleViolation)
			if !ok {
				t.Fatalf("expected *RuleViolation, got %T: %v", err, err)
			}
			if rv.Rule != tt.wantRule {
				t.Fatalf("expected rule %q, got %q (%v)", tt.wantRule, rv.Rule, rv)
			}
			if tt.wantIndex >= 0 && rv.LinkIndex != tt.wantIndex {
				t.Fatalf("expected violation at link index %d, got %d (%v)", tt.wantIndex, rv.LinkIndex, rv)
			}
		})
	}
}

func TestVerify_ScopeIntersection_KindAndBodyType(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		mutate   func(in *VerifyInput)
		wantRule string
	}{
		{
			name: "kind outside scope.kinds",
			mutate: func(in *VerifyInput) {
				in.Chain[1].Scope.Kinds = []string{"reply"}
				in.Kind = "message"
			},
			wantRule: RuleScopeIntersection,
		},
		{
			name: "body type outside scope.body_types",
			mutate: func(in *VerifyInput) {
				in.Chain[1].Scope.BodyTypes = []string{"data"}
				in.BodyType = "task"
			},
			wantRule: RuleScopeIntersection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, in, kr := baseline(t, now)
			_ = chain
			schedPriv := kr.add("assistant.acme.com", "k2")
			// Re-sign link 1 after mutating its scope (scope is covered by
			// the signature, so any scope edit invalidates the old sig).
			tt.mutate(&in)
			in.Chain[1].Sig = nil
			if err := in.Chain[1].Sign(schedPriv, "k2"); err != nil {
				t.Fatalf("re-sign: %v", err)
			}

			err := Verify(in)
			if err == nil {
				t.Fatalf("expected violation of rule %q, got nil", tt.wantRule)
			}
			rv, ok := err.(*RuleViolation)
			if !ok {
				t.Fatalf("expected *RuleViolation, got %T: %v", err, err)
			}
			if rv.Rule != tt.wantRule {
				t.Fatalf("expected rule %q, got %q (%v)", tt.wantRule, rv.Rule, rv)
			}
		})
	}
}

func TestVerify_ChainLengthBoundary(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	kr := newTestKeyring()

	// A chain of exactly MaxChainLength links, each continuous and validly
	// signed, MUST verify (rule 6 rejects only >8, not ==8).
	var chain []Link
	delegator := "user-root.example.com"
	priv := kr.add(delegator, "k1")
	for i := range MaxChainLength {
		delegate := fmt.Sprintf("d%d.example.com#agent", i+1)
		l := Link{
			Delegator: delegator,
			Delegate:  delegate,
			Scope:     Scope{}, // root has empty scope but expires within 24h of nonce
			Expires:   rfc3339(now.Add(time.Hour)),
			Nonce:     nonceAt(now),
		}
		if err := l.Sign(priv, "k1"); err != nil {
			t.Fatalf("sign link %d: %v", i, err)
		}
		chain = append(chain, l)
		delegator = delegate
		priv = kr.add(identity.DomainOf(delegate), "k1")
	}

	in := VerifyInput{
		Chain:      chain,
		From:       delegator, // last link's delegate
		To:         "irrelevant.example.com#x",
		Kind:       "message",
		BodyType:   "task",
		Now:        now,
		ResolveKey: kr.resolve,
	}
	if err := Verify(in); err != nil {
		t.Fatalf("chain of exactly %d links should verify, got: %v", MaxChainLength, err)
	}

	over := append(append([]Link{}, chain...), chain[len(chain)-1])
	in.Chain = over
	err := Verify(in)
	if err == nil {
		t.Fatal("expected chain_too_long violation for 9 links")
	}
	rv, ok := err.(*RuleViolation)
	if !ok || rv.Rule != RuleChainTooLong {
		t.Fatalf("expected RuleChainTooLong, got %v", err)
	}
}
