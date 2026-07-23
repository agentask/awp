package outbox

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"time"
)

// HTTPSender is the production Sender: POSTs to the destination domain's
// inbox over HTTPS (core §2.2), honoring only the numeric-seconds form of
// Retry-After (the common case; the HTTP-date form is not handled by this
// reference implementation).
type HTTPSender struct {
	Client *http.Client
	// InboxURL resolves a domain to its inbox POST endpoint. Production
	// wiring is internal/keyresolver.HTTPResolver.ResolveInbox — the
	// domain's own signed index (core §1.1 `inbox` field) is the source of
	// truth, not an out-of-band table.
	InboxURL func(domain string) (string, error)
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
			if secs, convErr := strconv.Atoi(ra); convErr == nil {
				retryAfter = time.Duration(secs) * time.Second
				hasRetryAfter = true
			}
		}
	}
	return resp.StatusCode, retryAfter, hasRetryAfter, nil
}
