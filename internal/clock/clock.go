// Package clock provides an injected time source so wall-clock reads stay
// out of business logic and tests never sleep real time (CLAUDE.md
// convention).
package clock

import "time"

// Clock is the sole source of "now" for any code that must reason about
// wall-clock time (TTL expiry, revocation windows, backoff scheduling).
type Clock interface {
	Now() time.Time
}

// Real is the production Clock, backed by time.Now.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fixed is a test Clock that always returns the same instant unless
// advanced.
type Fixed struct {
	t time.Time
}

// NewFixed returns a Fixed clock starting at t.
func NewFixed(t time.Time) *Fixed {
	return &Fixed{t: t}
}

func (f *Fixed) Now() time.Time { return f.t }

// Advance moves the fixed clock forward by d.
func (f *Fixed) Advance(d time.Duration) {
	f.t = f.t.Add(d)
}
