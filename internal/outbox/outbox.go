// Package outbox implements the awpd-outbox-v0.1.md delivery retry state
// machine: pre-attempt expiry, full-jitter backoff, 429 Retry-After
// honoring, and per-domain serial delivery.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
	"github.com/agentask/awp/internal/store"
)

// Sender delivers raw envelope bytes to a destination domain's inbox.
// err != nil means a transport-level failure (connection refused, timeout,
// DNS, ...), bucketed with 5xx per awpd-outbox §1. A non-nil err means
// status/retryAfter are meaningless.
type Sender interface {
	Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error)
}

// Config holds the awpd-outbox-v0.1.md §3 tunables this package uses.
type Config struct {
	BackoffBase time.Duration // default 1s
	BackoffCap  time.Duration // default 300s
	Workers     int           // default 8; global cap on concurrent in-flight attempts per ProcessDue call
}

// DefaultConfig returns the awpd-outbox-v0.1.md §3 defaults.
func DefaultConfig() Config {
	return Config{BackoffBase: time.Second, BackoffCap: 300 * time.Second, Workers: 8}
}

// Transition names the state-machine edge taken by one delivery attempt,
// for observability/testing.
type Transition string

const (
	TransitionNone              Transition = "none"
	TransitionDelivered         Transition = "delivered"
	TransitionRetry             Transition = "retry"
	TransitionRetryAfterHonored Transition = "retry_after_honored"
	TransitionDeadExpired       Transition = "dead_expired"
	TransitionDeadRejected      Transition = "dead_rejected"
)

// fullJitterBackoff implements awpd-outbox §2 rule 2:
// next_at = now + rand(0, min(cap, base*2^attempts)).
func fullJitterBackoff(base, capDur time.Duration, attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	// Guard against overflow; base*2^32 already dwarfs any sane cap.
	shift := min(attempts, 32)
	max := base * time.Duration(int64(1)<<shift)
	if max <= 0 || max > capDur {
		max = capDur
	}
	if max <= 0 {
		return 0
	}
	return time.Duration(mrand.Int64N(int64(max) + 1))
}

// Attempt performs exactly one delivery attempt for rec and applies the
// resulting state transition to st. It never mutates rec.Envelope
// (awpd-outbox §2 rule 4: "same bytes every attempt").
func Attempt(ctx context.Context, st *store.Store, clk clock.Clock, sender Sender, cfg Config, rec store.OutboxRecord) (Transition, error) {
	now := clk.Now()
	var env envelope.Envelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		return TransitionDeadRejected, st.MarkDead(rec.ID, "rejected", "unparseable envelope: "+err.Error(), now)
	}
	ts, err := time.Parse(time.RFC3339, env.Ts)
	if err != nil {
		return TransitionDeadRejected, st.MarkDead(rec.ID, "rejected", "unparseable ts: "+err.Error(), now)
	}
	expiry := ts.Add(time.Duration(env.TTL) * time.Second)

	// Rule 1: pre-attempt expiry check — never send an envelope the
	// receiver is obligated to 410.
	if now.After(expiry) {
		if err := st.MarkDead(rec.ID, "expired", "ttl exceeded before attempt", now); err != nil {
			return TransitionNone, err
		}
		return TransitionDeadExpired, nil
	}

	if err := st.MarkDelivering(rec.ID); err != nil {
		return TransitionNone, err
	}

	domain := identity.DomainOf(env.To)
	status, retryAfter, hasRetryAfter, sendErr := sender.Send(ctx, domain, rec.Envelope)
	if sendErr != nil {
		nextAt := now.Add(fullJitterBackoff(cfg.BackoffBase, cfg.BackoffCap, rec.Attempts))
		return TransitionRetry, st.MarkRetry(rec.ID, nextAt, sendErr.Error())
	}

	switch {
	case status >= 200 && status < 300:
		return TransitionDelivered, st.MarkDelivered(rec.ID)

	case status == 429:
		remaining := expiry.Sub(now)
		if hasRetryAfter && retryAfter <= remaining {
			return TransitionRetryAfterHonored, st.MarkRetry(rec.ID, now.Add(retryAfter), "429 Retry-After honored")
		}
		nextAt := now.Add(fullJitterBackoff(cfg.BackoffBase, cfg.BackoffCap, rec.Attempts))
		return TransitionRetry, st.MarkRetry(rec.ID, nextAt, "429 without a usable Retry-After, treated as 5xx")

	case status >= 500:
		nextAt := now.Add(fullJitterBackoff(cfg.BackoffBase, cfg.BackoffCap, rec.Attempts))
		return TransitionRetry, st.MarkRetry(rec.ID, nextAt, statusDetail(status))

	default: // 4xx other than 429: dead, not retryable
		return TransitionDeadRejected, st.MarkDead(rec.ID, "rejected", statusDetail(status), now)
	}
}

func statusDetail(status int) string {
	return fmt.Sprintf("status %d", status)
}

// ProcessDue drains up to maxCandidates due records and attempts delivery,
// enforcing awpd-outbox §2 rule 5 (per-domain serial delivery): at most one
// in-flight attempt per destination domain per call, with cfg.Workers
// bounding total concurrency across domains. Callers (a future cmd/awpd
// main loop) drive this on a timer; tests drive it directly against an
// injected clock, so no real sleeping is needed to exercise retry/backoff.
func ProcessDue(ctx context.Context, st *store.Store, clk clock.Clock, sender Sender, cfg Config, maxCandidates int) (int, error) {
	due, err := st.DueForDelivery(clk.Now(), maxCandidates)
	if err != nil {
		return 0, err
	}

	perDomain := make(map[string]store.OutboxRecord)
	for _, rec := range due {
		var env envelope.Envelope
		if err := json.Unmarshal(rec.Envelope, &env); err != nil {
			continue // Attempt will surface and dead-letter this on its own turn
		}
		domain := identity.DomainOf(env.To)
		if _, exists := perDomain[domain]; !exists {
			perDomain[domain] = rec
		}
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	processed := 0

	for _, rec := range perDomain {
		wg.Add(1)
		sem <- struct{}{}
		go func(rec store.OutboxRecord) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := Attempt(ctx, st, clk, sender, cfg, rec); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			processed++
			mu.Unlock()
		}(rec)
	}
	wg.Wait()
	return processed, firstErr
}
