// Package inbox implements the core §2.2 receiver gate: a transport-blind
// interface with a thin HTTP adapter, per CLAUDE.md ("HTTP and QUIC are
// thin adapters over it").
package inbox

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// KeyResolver resolves a domain+kid to that domain's currently trusted
// public key, with an explicit Refresh — the core §0.1 "re-fetch the
// signer's index once on failure before hard-failing (rotation race)"
// retry. A real implementation backs this with an HTTP fetch + the
// awpd-store `keys_cache` bucket; that wiring is deferred to whichever
// phase needs live cross-domain resolution (Phase 2 tests use fakes).
type KeyResolver interface {
	Resolve(domain, kid string) (ed25519.PublicKey, error)
	Refresh(domain string) error
}

// GateResult is the outcome of running an envelope through the gate: the
// HTTP-equivalent status plus, on any non-2xx outcome, the shared
// {code, detail, retryable} error (core §2.6). Envelope is populated
// whenever parsing succeeded, even on a later gate failure, so callers can
// log/attribute the rejection.
type GateResult struct {
	Status   int
	Err      *apperr.Error
	Envelope *envelope.Envelope
}

// Gate runs the core §2.2 receiver checks in strict order, each
// short-circuiting on failure.
type Gate struct {
	Store   *store.Store
	Keys    KeyResolver
	Clock   clock.Clock
	MaxSize int // 0 defaults to envelope.MaxSize
}

func (g *Gate) maxSize() int {
	if g.MaxSize > 0 {
		return g.MaxSize
	}
	return envelope.MaxSize
}

// Accept runs raw through gates 1-5 in order and returns the outcome.
func (g *Gate) Accept(raw []byte) GateResult {
	// Gate 1: parse (with size limit).
	if len(raw) > g.maxSize() {
		return reject(400, apperr.CodeMalformed, "envelope exceeds size limit", false)
	}
	var env envelope.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return reject(400, apperr.CodeMalformed, "invalid JSON: "+err.Error(), false)
	}
	if _, err := ulid.ParseStrict(strings.ToUpper(env.ID)); err != nil {
		return reject(400, apperr.CodeMalformed, "id is not a valid ULID: "+err.Error(), false)
	}
	if err := env.ValidateTTL(); err != nil {
		return reject(400, apperr.CodeMalformed, err.Error(), false)
	}
	if env.Sig == nil {
		return reject(400, apperr.CodeMalformed, "missing sig", false)
	}
	ts, err := time.Parse(time.RFC3339, env.Ts)
	if err != nil {
		return reject(400, apperr.CodeMalformed, "invalid ts: "+err.Error(), false)
	}

	// Gate 2: now <= ts + ttl.
	expiry := ts.Add(time.Duration(env.TTL) * time.Second)
	now := g.Clock.Now()
	if now.After(expiry) {
		return rejectWithEnvelope(410, apperr.CodeExpired, "envelope expired", false, &env)
	}

	// Gate 3: verify sig, one index re-fetch on first failure (core §0.1).
	domain := identity.DomainOf(env.From)
	verify := func() error {
		pub, err := g.Keys.Resolve(domain, env.Sig.Kid)
		if err != nil {
			return err
		}
		return env.Verify(pub)
	}
	if err := verify(); err != nil {
		_ = g.Keys.Refresh(domain)
		if err2 := verify(); err2 != nil {
			return rejectWithEnvelope(401, apperr.CodeUnauthorized, "signature verification failed: "+err2.Error(), false, &env)
		}
	}

	// Gate 4 (dedupe) + Gate 5 (durable enqueue): atomic in the store.
	alreadySeen, err := g.Store.AcceptInbound(env.ID, expiry, raw)
	if err != nil {
		return rejectWithEnvelope(503, apperr.CodeCapacity, "enqueue failed: "+err.Error(), true, &env)
	}
	if alreadySeen {
		return GateResult{Status: 200, Envelope: &env}
	}
	return GateResult{Status: 202, Envelope: &env}
}

func reject(status int, code, detail string, retryable bool) GateResult {
	return rejectWithEnvelope(status, code, detail, retryable, nil)
}

func rejectWithEnvelope(status int, code, detail string, retryable bool, env *envelope.Envelope) GateResult {
	return GateResult{
		Status:   status,
		Err:      &apperr.Error{Code: code, Detail: detail, Retryable: retryable},
		Envelope: env,
	}
}
