package conformance

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 §1.3 mandates SHA-1 for the handshake accept key; not a security use of the hash.
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/identity"
)

// remainingWSChecks lists the awp-ws §7 checklist.
func remainingWSChecks() []checkMeta {
	return []checkMeta{
		{"ws-7.1", "Advertises awp-ws/1 via the signed index transports field, with a wss:// endpoint."},
		{"ws-7.2", "Completes the RFC 6455 handshake with a correct Sec-WebSocket-Accept."},
		{"ws-7.3", "Identical gate outcomes to its own HTTPS inbox for identical (fresh) envelopes."},
		{"ws-7.4", "Handles >=100 concurrent envelopes multiplexed on one connection."},
		{"ws-7.5", "Cross-transport dedupe: envelope delivered over awp-ws/1 then resent over HTTPS is deduped, not double-processed."},
	}
}

func runWSChecks(ctx context.Context, domain string, idx *identity.Index, opts Options) []CheckResult {
	meta := remainingWSChecks()
	var endpoint string
	for _, t := range idx.Transports {
		if t.Proto == "awp-ws/1" {
			endpoint = t.Endpoint
			break
		}
	}
	if endpoint == "" {
		results := []CheckResult{{ID: meta[0].id, Description: meta[0].desc, Status: Pass, Detail: "no awp-ws/1 transport advertised; HTTPS-only is spec-compliant (awp-ws §2)"}}
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Skip, Detail: "no awp-ws/1 endpoint advertised"})
		}
		return results
	}
	if !strings.HasPrefix(endpoint, "wss://") {
		results := []CheckResult{{ID: meta[0].id, Description: meta[0].desc, Status: Fail, Detail: fmt.Sprintf("endpoint %q is not wss:// (awp-ws §1: ws:// is rejected)", endpoint)}}
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Skip, Detail: "endpoint is not wss://"})
		}
		return results
	}

	results := []CheckResult{{ID: meta[0].id, Description: meta[0].desc, Status: Pass, Detail: "advertises awp-ws/1 at " + endpoint}}

	conn, err := dialWSProbe(ctx, opts, endpoint)
	if err != nil {
		detail := "handshake failed: " + err.Error()
		for _, m := range meta[1:] {
			results = append(results, CheckResult{ID: m.id, Description: m.desc, Status: Fail, Detail: detail})
		}
		return results
	}
	defer conn.Close()
	results = append(results, CheckResult{ID: meta[1].id, Description: meta[1].desc, Status: Pass, Detail: "RFC 6455 handshake completed, Sec-WebSocket-Accept verified"})

	results = append(results, checkWSGateEquivalence(conn, domain, opts))
	results = append(results, checkWSConcurrency(ctx, opts, endpoint))
	results = append(results, checkWSCrossTransportDedupe(ctx, conn, domain, idx, opts))
	return results
}

// --- an INDEPENDENT, minimal RFC 6455 client, deliberately not importing
// internal/wstrans — mirroring quic8.go's own stated principle: "a
// black-box conformance checker should speak the wire format itself, not
// reuse the very implementation it might be checking." ---

const wsProbeMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsProbeAcceptKey(clientKey string) string {
	h := sha1.New() //nolint:gosec // see import comment
	h.Write([]byte(clientKey))
	h.Write([]byte(wsProbeMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsProbeConn struct {
	raw net.Conn
	br  *bufio.Reader
}

func (c *wsProbeConn) Close() error { return c.raw.Close() }

func dialWSProbe(ctx context.Context, opts Options, wssURL string) (*wsProbeConn, error) {
	u, err := url.Parse(wssURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	var tlsConf *tls.Config
	if opts.QUICTLSConfig != nil {
		tlsConf = opts.QUICTLSConfig.Clone() // reuse the same "trust this test's self-signed cert" override
	} else {
		tlsConf = &tls.Config{}
	}
	tlsConf.ServerName = u.Hostname()

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: tlsConf}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		rawConn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])
	req := "GET " + u.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := rawConn.Write([]byte(req)); err != nil {
		rawConn.Close()
		return nil, err
	}

	br := bufio.NewReader(rawConn)
	line, err := br.ReadString('\n')
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) < 2 {
		rawConn.Close()
		return nil, fmt.Errorf("malformed status line %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status != 101 {
		rawConn.Close()
		return nil, fmt.Errorf("status %q, want 101", parts[1])
	}
	var gotAccept string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Sec-WebSocket-Accept") {
			gotAccept = strings.TrimSpace(v)
		}
	}
	if gotAccept != wsProbeAcceptKey(key) {
		rawConn.Close()
		return nil, fmt.Errorf("Sec-WebSocket-Accept mismatch")
	}
	return &wsProbeConn{raw: rawConn, br: br}, nil
}

const wsProbeOpcodeBinary = 0x2

func writeWSProbeFrame(conn *wsProbeConn, payload []byte) error {
	var header []byte
	header = append(header, 0x80|wsProbeOpcodeBinary)
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		header = append(header, lenBuf[:]...)
	default:
		header = append(header, 0x80|127)
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(n))
		header = append(header, lenBuf[:]...)
	}
	if _, err := conn.raw.Write(header); err != nil {
		return err
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	if _, err := conn.raw.Write(mask[:]); err != nil {
		return err
	}
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	_, err := conn.raw.Write(masked)
	return err
}

func readWSProbeFrame(conn *wsProbeConn) ([]byte, error) {
	var head [2]byte
	if _, err := readFull(conn.br, head[:]); err != nil {
		return nil, err
	}
	length := uint64(head[1] & 0x7F)
	switch length {
	case 126:
		var lenBuf [2]byte
		if _, err := readFull(conn.br, lenBuf[:]); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(lenBuf[:]))
	case 127:
		var lenBuf [8]byte
		if _, err := readFull(conn.br, lenBuf[:]); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(lenBuf[:])
	}
	payload := make([]byte, length)
	if _, err := readFull(conn.br, payload); err != nil {
		return nil, err
	}
	return payload, nil // server frames are unmasked (RFC 6455 §5.3)
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := br.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func sendEnvelopeOverWS(conn *wsProbeConn, raw []byte) (int, error) {
	if err := writeWSProbeFrame(conn, raw); err != nil {
		return 0, err
	}
	respBuf, err := readWSProbeFrame(conn)
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

func checkWSGateEquivalence(conn *wsProbeConn, domain string, opts Options) CheckResult {
	meta := remainingWSChecks()[2]
	fromDomain, _, sign := ephemeralSigner()

	if status, err := sendEnvelopeOverWS(conn, []byte(`{not valid json`)); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 400 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("malformed: got %d, want 400", status)}
	}

	expiredRaw, _, err := buildEnvelope(fromDomain, domain, opts.now().Add(-2*time.Hour), 3600, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status, err := sendEnvelopeOverWS(conn, expiredRaw); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 410 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("expired: got %d, want 410", status)}
	}

	unknownSignerRaw, _, err := buildEnvelope(fromDomain, domain, opts.now(), 3600, sign)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status, err := sendEnvelopeOverWS(conn, unknownSignerRaw); err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	} else if status != 401 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("unknown signer: got %d, want 401", status)}
	}

	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass}
}

// checkWSConcurrency dials its OWN connection (rather than reusing the
// caller's) — awp-ws-v0.1.md §4/§7 item 4 is specifically about many
// envelopes multiplexed on ONE connection, so this must not interleave
// with the sequential gate-equivalence probe's request/response pairing
// on the shared conn.
func checkWSConcurrency(ctx context.Context, opts Options, endpoint string) CheckResult {
	meta := remainingWSChecks()[3]
	conn, err := dialWSProbe(ctx, opts, endpoint)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	defer conn.Close()

	// This probe sends the SAME malformed body n times — every response
	// is identically 400, so unlike internal/wstrans's real id-based
	// correlation, this check doesn't need to match a specific response
	// to a specific send; it only needs n writes to succeed and n reads
	// to each come back 400, proving the connection sustains that many
	// envelopes without deadlocking or dropping any.
	const n = 100
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			writeMu.Lock()
			err := writeWSProbeFrame(conn, []byte(`{not valid json`))
			writeMu.Unlock()
			if err != nil {
				errs[i] = err
				return
			}
		}(i)
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("send %d: %v", i, errs[i])}
		}
	}
	for i := range n {
		respBuf, err := readWSProbeFrame(conn)
		if err != nil {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("read %d: %v", i, err)}
		}
		var status struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(respBuf, &status); err != nil {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("read %d: unmarshal: %v", i, err)}
		}
		if status.Status != 400 {
			return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("response %d: got status %d, want 400", i, status.Status)}
		}
	}
	return CheckResult{ID: meta.id, Description: meta.desc, Status: Pass, Detail: fmt.Sprintf("%d concurrent envelopes handled on one connection", n)}
}

func checkWSCrossTransportDedupe(ctx context.Context, conn *wsProbeConn, domain string, idx *identity.Index, opts Options) CheckResult {
	meta := remainingWSChecks()[4]
	if opts.CallerPriv == nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Skip, Detail: "requires --key/--kid, same as core-5.2-accept-and-dedupe"}
	}
	raw, env, err := buildEnvelope(opts.CallerDomain, domain, opts.now(), 3600, func(e *envelope.Envelope) error {
		return e.Sign(opts.CallerPriv, opts.CallerKid)
	})
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	status1, err := sendEnvelopeOverWS(conn, raw)
	if err != nil {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: err.Error()}
	}
	if status1 != 202 {
		return CheckResult{ID: meta.id, Description: meta.desc, Status: Fail, Detail: fmt.Sprintf("over awp-ws/1: got %d, want 202 (id=%s)", status1, env.ID)}
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
