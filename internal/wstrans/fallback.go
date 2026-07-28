package wstrans

import (
	"context"
	"time"
)

// sender is the minimal shape any transport's Sender satisfies — declared
// locally to avoid this package depending on internal/outbox for a
// one-method interface, mirroring internal/quictrans.FallbackSender's
// own local `sender` interface exactly.
type sender interface {
	Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error)
}

// FallbackSender tries Primary (awp-ws/1) first; on any error —
// handshake failure, connection failure, or the domain advertising no
// awp-ws/1 transport at all — it falls back to Fallback with the exact
// same bytes and domain, per awp-ws-v0.1.md §5 rule 2. Composes with
// internal/quictrans.FallbackSender: wrap that one's result as this
// FallbackSender's own Fallback to get a WS -> awp/1 -> HTTPS chain
// (awp-ws-v0.1.md §5's reference ordering) — see internal/daemon's
// wiring.
type FallbackSender struct {
	Primary  sender
	Fallback sender
}

func (f *FallbackSender) Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	status, retryAfter, hasRetryAfter, err = f.Primary.Send(ctx, domain, raw)
	if err == nil {
		return status, retryAfter, hasRetryAfter, nil
	}
	return f.Fallback.Send(ctx, domain, raw)
}
