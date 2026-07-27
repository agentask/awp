// Package conformance implements `awp conformance <domain>`: the core §5
// and awp-quic §8 checklists run as black-box probes against any AWP
// implementation reachable over the network, plus one check beyond either
// checklist (awp-sig §3 response signing — see sync_sig.go's doc comment
// for why).
//
// Scope note (flagged, not silently assumed): two core §5 items — "emits
// error envelopes for unknown body types" and "enforces the two-party
// thread invariant" — describe internal processing/state that a
// stateless, single-invocation CLI probing an implementation from outside
// cannot observe through the wire protocol alone (there is no spec-defined
// API to ask a domain "what happened to the envelope I sent you"). Those
// checks report Skip with a reason rather than a fabricated Pass/Fail.
package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

// Status is a single check's outcome.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

// CheckResult is one checklist item's outcome.
type CheckResult struct {
	ID          string
	Description string
	Status      Status
	Detail      string
}

// Report is the full result of one conformance run.
type Report struct {
	Domain  string
	Results []CheckResult
}

// OK reports whether every check passed or was skipped (no failures).
func (r Report) OK() bool {
	for _, c := range r.Results {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

// Options configures a conformance run.
type Options struct {
	// BaseURL maps a domain to the base URL its index/inbox are served
	// from. Production default is "https://" + domain; tests override this
	// to point at local instances.
	BaseURL func(domain string) string
	HTTP    *http.Client
	Clock   func() time.Time // defaults to time.Now

	// Caller identity, for checks that need to send a TRUSTED envelope
	// (dedupe, gate-5 accept, QUIC gate-equivalence, cross-transport
	// dedupe). These checks Skip if CallerPriv is nil — a domain's own
	// conformance self-run (CLAUDE.md's "awpd passes its own conformance
	// run") supplies its own identity here, since it inherently trusts
	// itself.
	CallerDomain string
	CallerKid    string
	CallerPriv   ed25519.PrivateKey

	// QUICTLSConfig is used to dial the target's advertised awp/1
	// endpoint, if any. nil uses default system root CAs (real WebPKI) —
	// tests override this with a pool trusting their self-signed test
	// certificate.
	QUICTLSConfig *tls.Config
}

func (o Options) baseURL(domain string) string {
	if o.BaseURL != nil {
		return o.BaseURL(domain)
	}
	return "https://" + domain
}

func (o Options) client() *http.Client {
	if o.HTTP != nil {
		return o.HTTP
	}
	return http.DefaultClient
}

func (o Options) now() time.Time {
	if o.Clock != nil {
		return o.Clock()
	}
	return time.Now()
}

// Run executes the full core §5 + awp-quic §8 checklist against domain.
func Run(ctx context.Context, domain string, opts Options) Report {
	report := Report{Domain: domain}
	add := func(r CheckResult) { report.Results = append(report.Results, r) }

	idx, err := fetchIndex(ctx, opts, domain)
	add(checkSignedIndex(idx, err))
	if err != nil {
		// Nothing else is reachable without a valid index — every
		// remaining check is meaningless, not merely unverified.
		for _, c := range remainingCoreChecks() {
			add(CheckResult{ID: c.id, Description: c.desc, Status: Skip, Detail: "index fetch/verification failed; see core-5.1"})
		}
		for _, c := range remainingQUICChecks() {
			add(CheckResult{ID: c.id, Description: c.desc, Status: Skip, Detail: "index fetch/verification failed; see core-5.1"})
		}
		return report
	}

	for _, result := range runCoreChecks(ctx, domain, idx, opts) {
		add(result)
	}
	for _, result := range runQUICChecks(ctx, domain, idx, opts) {
		add(result)
	}
	// Beyond the two named checklists (see sync_sig.go's doc comment).
	add(checkResponseSigning(ctx, opts, idx))
	return report
}

func fetchIndex(ctx context.Context, opts Options, domain string) (*identity.Index, error) {
	url := opts.baseURL(domain) + "/.well-known/awp.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := opts.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read index body: %w", err)
	}
	var idx identity.Index
	if err := json.Unmarshal(buf, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	return &idx, nil
}

func checkSignedIndex(idx *identity.Index, fetchErr error) CheckResult {
	const id = "core-5.1"
	const desc = "Serves a valid signed domain index over TLS with >=1 active key."
	if fetchErr != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: fetchErr.Error()}
	}
	if err := idx.VerifySelfSig(); err != nil {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "index signature invalid: " + err.Error()}
	}
	active := 0
	for _, k := range idx.Keys {
		if !k.Revoked {
			active++
		}
	}
	if active == 0 {
		return CheckResult{ID: id, Description: desc, Status: Fail, Detail: "no active (non-revoked) key in index"}
	}
	return CheckResult{ID: id, Description: desc, Status: Pass, Detail: fmt.Sprintf("%d active key(s)", active)}
}

// buildEnvelope constructs a probe envelope; sign is called on the fully
// populated struct before marshaling.
func buildEnvelope(from, to string, ts time.Time, ttl int, sign func(*envelope.Envelope) error) ([]byte, *envelope.Envelope, error) {
	e := &envelope.Envelope{
		Awp: "0.1", ID: envelope.NewID(), Kind: "message",
		From: from, To: to, Thread: envelope.NewID(),
		Ts: ts.UTC().Format("2006-01-02T15:04:05.000Z"), TTL: ttl,
		Body: json.RawMessage(`{"type":"text","text":"awp conformance probe"}`),
	}
	if err := sign(e); err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(e)
	return raw, e, err
}

// ephemeralSigner returns a throwaway (unregistered anywhere) domain, kid,
// and signer — for probes that specifically want a signature the target
// has never heard of.
func ephemeralSigner() (domain, kid string, sign func(*envelope.Envelope) error) {
	_, priv, _ := ed25519.GenerateKey(nil)
	domain = "conformance-probe-" + envelope.NewID() + ".invalid"
	kid = "k1"
	sign = func(e *envelope.Envelope) error {
		return e.Sign(priv, kid)
	}
	return domain, kid, sign
}
