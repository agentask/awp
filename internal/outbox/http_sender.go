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
