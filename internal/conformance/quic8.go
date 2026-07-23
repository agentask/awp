package conformance

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

// remainingQUICChecks lists the awp-quic §8 checklist.
func remainingQUICChecks() []checkMeta {
	return []checkMeta{
		{"quic-8.1", "Advertises awp/1 via the signed index transports field."},
		{"quic-8.2", "ALPN awp/1 negotiates and the TLS certificate validates."},
		{"quic-8.3", "Identical gate outcomes to its own HTTPS inbox for identical (fresh) envelopes."},
		{"quic-8.4", "Handles >=100 concurrent envelope streams."},
		{"quic-8.5", "Cross-transport dedupe: envelope delivered over awp/1 then resent over HTTPS is deduped, not double-processed."},
	}
}

func runQUICChecks(ctx context.Context, domain string, idx *identity.Index, opts Options) []CheckResult {
	meta := remainingQUICChecks()
	var endpoint string
	for _, t := range idx.Transports {
		if t.Proto == "awp/1" {
			endpoint = t.Endpoint
			break
		}
	}
	if endpoint == "" {
		results := []CheckResult{{ID: meta[0].id, Description: meta[0].desc, Status: Pass, Detail: "no awp/1 transport advertised; HTTPS-only is spec-compliant (awp-quic §2)"}}
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Skip, Detail: "no awp/1 endpoint advertised"})
		}
		return results
	}

	results := []CheckResult{{ID: meta[0].id, Description: meta[0].desc, Status: Pass, Detail: "advertises awp/1 at " + endpoint}}

	conn, err := dialQUIC(ctx, opts, domain, endpoint)
	if err != nil {
		detail := "dial/handshake failed: " + err.Error()
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Fail, Detail: detail})
		}
		return results
	}
	defer func() { _ = conn.CloseWithError(0, "conformance check complete") }()
	results = append(results, CheckResult{ID: meta[1].id, Description: meta[1].desc, Status: Pass, Detail: "ALPN awp/1 negotiated, TLS handshake completed"})

	results = append(results, checkQUICGateEquivalence(ctx, conn, domain, opts))
	results = append(results, checkQUICConcurrency(ctx, conn))
	results = append(results, checkQUICCrossTransportDedupe(ctx, conn, domain, idx, opts))
	return results
}

func dialQUIC(ctx context.Context, opts Options, domain, endpoint string) (*quic.Conn, error) {
	var tlsConf *tls.Config
	if opts.QUICTLSConfig != nil {
		tlsConf = opts.QUICTLSConfig.Clone()
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.ServerName = domain
	tlsConf.NextProtos = []string{"awp/1"}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return quic.DialAddr(dialCtx, endpoint, tlsConf, nil)
}

// writeQUICFrame/readQUICFrame implement the awp-quic §3 wire framing
// (4-byte big-endian length prefix + JSON payload) as an INDEPENDENT
// client — this package deliberately does not import internal/quictrans,
// since a black-box conformance checker should speak the wire format
// itself, not reuse the very implementation it might be checking.
func writeQUICFrame(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readQUICFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func sendEnvelopeOverQUIC(ctx context.Context, conn *quic.Conn, raw []byte) (int, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	if err := writeQUICFrame(stream, raw); err != nil {
		return 0, err
	}
	if err := stream.Close(); err != nil {
		return 0, err
	}
	respBuf, err := readQUICFrame(stream)
	if err != nil {
		return 0, err
	}
	var status struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(respBuf, &status); err != nil {
		return 0, err
	}
	return status.Status, nil
}

func checkQUICGateEquivalence(ctx context.Context, conn *quic.Conn, domain string, opts Options) CheckResult {
	meta := remainingQUICChecks()[2]
	fromDomain, _, sign := ephemeralSigner()

	if status, err := sendEnvelopeOverQUIC(ctx, conn, []byte(`{not valid json`)); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 400 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("malformed: got %d, want 400", status)}
	}

	expiredRaw, _, err := buildEnvelope(fromDomain, domain, opts.now().Add(-2*time.Hour), 3600, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status, err := sendEnvelopeOverQUIC(ctx, conn, expiredRaw); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 410 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("expired: got %d, want 410", status)}
	}

	unknownSignerRaw, _, err := buildEnvelope(fromDomain, domain, opts.now(), 3600, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status, err := sendEnvelopeOverQUIC(ctx, conn, unknownSignerRaw); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 401 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("unknown signer: got %d, want 401", status)}
	}

	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

func checkQUICConcurrency(ctx context.Context, conn *quic.Conn) CheckResult {
	meta := remainingQUICChecks()[3]
	const n = 100
	var wg sync.WaitGroup
	statuses := make([]int, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			statuses[i], errs[i] = sendEnvelopeOverQUIC(ctx, conn, []byte(`{not valid json`))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("stream %d: %v", i, err)}
		}
		if statuses[i] != 400 {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("stream %d: got status %d, want 400", i, statuses[i])}
		}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass, Detail: fmt.Sprintf("%d concurrent streams handled", n)}
}

func checkQUICCrossTransportDedupe(ctx context.Context, conn *quic.Conn, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingQUICChecks()[4]
	if opts.CallerPriv == nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Skip, Detail: "requires --key/--kid, same as core-5.2-accept-and-dedupe"}
	}
	raw, env, err := buildEnvelope(opts.CallerDomain, domain, opts.now(), 3600, func(e *envelope.Envelope) error {
		return e.Sign(opts.CallerPriv, opts.CallerKid)
	})
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status1, err := sendEnvelopeOverQUIC(ctx, conn, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status1 != 202 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("over awp/1: got %d, want 202 (id=%s)", status1, env.ID)}
	}
	status2, err := postEnvelope(ctx, opts, idx.Inbox, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status2 != 200 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("resent over HTTPS: got %d, want 200 (deduped)", status2)}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}
