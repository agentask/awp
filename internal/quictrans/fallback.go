package quictrans

import (
	"context"
	"time"
)

// sender is the minimal shape both the QUIC Sender and any HTTPS sender
// (internal/outbox.HTTPSender) satisfy — declared locally to avoid this
// package depending on internal/outbox for a one-method interface.
type sender interface {
	Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error)
}

// FallbackSender tries Primary (QUIC) first; on any error — connection
// failure, timeout, or the domain advertising no awp/1 transport at all —
// it falls back to Fallback (HTTPS) with the exact same bytes and domain,
// per awp-quic §5 rule 2. From the outbox state machine's point of view
// this whole dance is a single Sender.Send call, i.e. one attempt: "a
// failed QUIC attempt and a failed HTTPS attempt are the same
// queued-with-backoff transition" (awp-quic §5 rule 2 / awpd-outbox
// integration note) — FallbackSender is what makes that true, by never
// surfacing the QUIC attempt as a separate outbox-visible event.
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
