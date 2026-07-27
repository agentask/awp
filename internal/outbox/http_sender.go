package outbox

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/agentask/awp/internal/clock"
)

// HTTPSender is the production Sender: POSTs to the destination domain's
// inbox over HTTPS (core §2.2), honoring both the numeric-seconds and
// HTTP-date forms of Retry-After (RFC 9110 §10.2.3).
type HTTPSender struct {
	Client *http.Client
	// InboxURL resolves a domain to its inbox POST endpoint. Production
	// wiring is internal/keyresolver.HTTPResolver.ResolveInbox — the
	// domain's own signed index (core §1.1 `inbox` field) is the source of
	// truth, not an out-of-band table.
	InboxURL func(domain string) (string, error)
	// Clock is used only to convert an HTTP-date Retry-After (an absolute
	// time) into the relative time.Duration Sender.Send returns — the
	// numeric-seconds form needs no clock at all. nil uses clock.Real{}.
	Clock clock.Clock
	// WakeURL resolves a domain to its awp-push-v0.1.md §2 wake endpoint.
	// ok=false means the domain declares none. Production wiring is
	// internal/keyresolver.HTTPResolver.ResolveWake. A nil WakeURL means
	// HTTPSender implements no wake capability at all (Attempt's type
	// assertion on outbox.WakeNotifier still succeeds either way — this
	// field just makes NotifyWake a no-op when unset).
	WakeURL func(domain string) (endpoint string, ok bool, err error)
	// WakeTimeout bounds how long NotifyWake waits for the wake POST
	// before giving up; it must never block the outbox's own attempt
	// loop for long. Default 5s.
	WakeTimeout time.Duration
}

func (h *HTTPSender) clockOrReal() clock.Clock {
	if h.Clock != nil {
		return h.Clock
	}
	return clock.Real{}
}

// parseRetryAfter accepts either form RFC 9110 §10.2.3 permits: delta-
// seconds, or an HTTP-date. now is only consulted for the HTTP-date form,
// to produce a relative duration exactly like the delta-seconds form
// already is one. A duration that would be negative (a date already in
// the past) clamps to zero rather than telling the outbox to retry
// "before now".
func parseRetryAfter(header string, now time.Time) (time.Duration, bool) {
	if secs, err := strconv.Atoi(header); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(header); err == nil {
		if d := at.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func (h *HTTPSender) Send(ctx context.Context, domain string, raw []byte) (status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	url, err := h.InboxURL(domain)
	if err != nil {
		return 0, 0, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, 0, false, err
	}
	req.Header.Set("Content-Type", "application/awp+json")

	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			retryAfter, hasRetryAfter = parseRetryAfter(ra, h.clockOrReal().Now())
		}
	}
	return resp.StatusCode, retryAfter, hasRetryAfter, nil
}

// NotifyWake implements outbox.WakeNotifier (awp-push-v0.1.md §3): an
// unsigned, empty-body, best-effort POST to domain's declared wake
// endpoint, if any. Errors and non-2xx responses are deliberately
// discarded — per spec, the wake POST's outcome MUST NOT influence the
// outbox state machine, so there is nothing for a caller to do with them.
func (h *HTTPSender) NotifyWake(ctx context.Context, domain string) {
	if h.WakeURL == nil {
		return
	}
	endpoint, ok, err := h.WakeURL(domain)
	if err != nil || !ok || endpoint == "" {
		return
	}

	timeout := h.WakeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	wakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(wakeCtx, http.MethodPost, endpoint, nil)
	if err != nil {
		return
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
