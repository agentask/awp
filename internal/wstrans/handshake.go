package wstrans

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 §1.3 mandates SHA-1 for the handshake accept key; not a security use of the hash.
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// websocketMagicGUID is the fixed RFC 6455 §1.3 constant XORed (well,
// concatenated-then-hashed) into every handshake's accept key — a
// protocol constant, not a secret.
const websocketMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// acceptKey computes RFC 6455 §1.3's Sec-WebSocket-Accept value from the
// client's Sec-WebSocket-Key.
func acceptKey(clientKey string) string {
	h := sha1.New() //nolint:gosec // see import comment
	h.Write([]byte(clientKey))
	h.Write([]byte(websocketMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Conn wraps the raw byte stream underlying a WebSocket connection after
// its handshake completes — reads go through any bytes already buffered
// during the handshake (br), then the raw connection; writes and Close
// go straight to the connection. Used identically by both the server
// (after Upgrade) and the client (after Dial).
type Conn struct {
	raw net.Conn
	br  *bufio.Reader
}

func (c *Conn) Read(p []byte) (int, error)  { return c.br.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.raw.Write(p) }
func (c *Conn) Close() error                { return c.raw.Close() }

// Upgrade performs the server side of the RFC 6455 §4 handshake over an
// in-flight HTTP request, hijacking the underlying connection on
// success. r MUST NOT have had its body read or response already
// written — call this as the entire body of the handler mounted at the
// awp-ws/1 path (awp-ws-v0.1.md §1/§2).
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("wstrans: missing or wrong Upgrade header")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errors.New("wstrans: missing or unsupported Sec-WebSocket-Version (want 13)")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("wstrans: missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("wstrans: response writer does not support hijacking")
	}
	raw, rw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("wstrans: hijack: %w", err)
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		raw.Close()
		return nil, fmt.Errorf("wstrans: write handshake response: %w", err)
	}
	if err := rw.Flush(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("wstrans: flush handshake response: %w", err)
	}

	return &Conn{raw: raw, br: rw.Reader}, nil
}

// Dial performs the client side of the RFC 6455 §4 handshake against a
// wss:// endpoint (awp-ws-v0.1.md §1) and returns the resulting Conn.
// tlsConfig's ServerName is set per-dial from the URL's host if unset on
// the passed-in config's clone — the caller's base config should
// generally leave it unset (mirrors internal/quictrans.Sender's own
// per-dial SNI convention).
func Dial(wssURL string, tlsConfig *tls.Config, timeout time.Duration) (*Conn, error) {
	u, err := url.Parse(wssURL)
	if err != nil {
		return nil, fmt.Errorf("wstrans: parse endpoint %q: %w", wssURL, err)
	}
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("wstrans: endpoint %q is not wss:// (awp-ws-v0.1.md §1: ws:// is rejected)", wssURL)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	tlsConf := tlsConfig.Clone()
	if tlsConf.ServerName == "" {
		tlsConf.ServerName = u.Hostname()
	}

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("wstrans: dial %s: %w", host, err)
	}
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("wstrans: TLS handshake with %s: %w", host, err)
	}

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("wstrans: generate Sec-WebSocket-Key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	path := u.RequestURI()
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("wstrans: write handshake request: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	status, headers, err := readHandshakeStatusLine(br)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	if status != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("wstrans: handshake with %s: status %d, want 101", host, status)
	}
	if !strings.EqualFold(headers.Get("Upgrade"), "websocket") {
		tlsConn.Close()
		return nil, fmt.Errorf("wstrans: handshake with %s: response missing Upgrade: websocket", host)
	}
	want := acceptKey(key)
	if headers.Get("Sec-WebSocket-Accept") != want {
		tlsConn.Close()
		return nil, fmt.Errorf("wstrans: handshake with %s: Sec-WebSocket-Accept mismatch", host)
	}

	return &Conn{raw: tlsConn, br: br}, nil
}

// readHandshakeStatusLine hand-parses the HTTP/1.1 status line and
// headers of a handshake response — deliberately not net/http.ReadResponse,
// whose body-framing assumptions (Content-Length/chunked) don't apply to
// a 101 response that's about to stop being HTTP at all; see this
// package's own doc comment on hand-rolling exactly what's needed.
func readHandshakeStatusLine(br *bufio.Reader) (status int, headers http.Header, err error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, fmt.Errorf("wstrans: read status line: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, nil, fmt.Errorf("wstrans: malformed status line %q", line)
	}
	status, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("wstrans: malformed status code in %q: %w", line, err)
	}

	headers = http.Header{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, nil, fmt.Errorf("wstrans: read headers: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return status, headers, nil
}
