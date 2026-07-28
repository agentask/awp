# AWP-WS v0.1 — WebSocket Transport Binding

**Status:** draft. Optional transport for **envelope delivery only** —
the identical scope `awp-quic-v0.1.md` chose, for the identical reason:
sync tool calls are HTTP-native (RFC 9421) and this binding does not
re-specify request signing outside HTTP. HTTPS remains the mandatory
floor (core §6); `awp/1` (QUIC) and this binding are both negotiated
upgrades, never replacements.

## 0. Why this exists next to `awp/1`

This is not a second way to do what QUIC already does — it is a
different tradeoff on the same problem (avoid one HTTP request's setup
cost per envelope by reusing a connection):

- **QUIC needs a new UDP listener and its own port.** Some networks
  (corporate egress filters, certain load balancers/CDNs) block or
  mishandle UDP entirely. WebSocket is an HTTP/1.1 `Upgrade` — it
  travels through anything plain HTTPS already travels through, on the
  same port, and needs no new listener at all: `internal/wstrans`'s
  server side is one more handler on the daemon's existing `http.Server`
  mux, not a second bound socket.
- **QUIC's payoff (no head-of-line blocking between streams) doesn't
  apply here.** WebSocket is a single ordered byte stream; concurrent
  envelopes on one connection serialize, same as HTTP/1.1 pipelining
  would. The win this binding offers is strictly "pay the TLS+TCP
  handshake once, not once per envelope" — smaller than QUIC's, but
  free of QUIC's deployment cost.
- A domain MAY advertise both, neither, or either. Senders that support
  both try WebSocket before QUIC before HTTPS in this reference
  implementation's default ordering (§5), but no requirement forces that
  order — both are optional upgrades over the same HTTPS floor.

**This does not reopen core §6's "no raw-TLS replacement transport"
decision.** WebSocket is not a bespoke TLS wire protocol competing with
HTTP — it *is* HTTP: an `Upgrade` negotiated inside an ordinary HTTP/1.1
request/response, terminating in the same WebPKI-validated `wss://`
connection HTTPS already uses. It is the literal "upgrade inside the
deployable envelope" core §6 describes QUIC as, applied to a mechanism
that needs zero new infrastructure.

## 1. Connection

- `wss://` only — the WebSocket protocol's TLS form (RFC 6455 §11.2's
  `ws`/`wss` split maps directly to HTTP's `http`/`https`; this binding
  only ever uses the TLS one, same WebPKI trust root as HTTPS, no new
  PKI, matching L0). A bare `ws://` (unencrypted) endpoint MUST be
  rejected by conforming senders.
- Handshake: RFC 6455 §4 — an HTTP/1.1 `GET` with `Upgrade: websocket`,
  `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`; the server responds
  `101 Switching Protocols` with a matching `Sec-WebSocket-Accept`
  (`base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`, RFC
  6455 §1.3). No WebSocket subprotocol or extension is negotiated —
  `Sec-WebSocket-Protocol` is absent on both sides.
- The daemon mounts the handshake at the same path (§2) served over its
  existing HTTPS listener — there is no separate bind address, unlike
  awp-quic's own UDP port.

## 2. Advertisement

Domain index (core §1.1) gains an entry in the existing `transports[]`
array (already generic across `proto` values, per `awp-quic-v0.1.md`
§2 — no schema change needed):

```json
"transports": [
  { "proto": "awp-ws/1", "endpoint": "wss://example.com/awp/ws" }
]
```

- Unlike `awp/1`'s `host:port` endpoint form (QUIC has no path routing
  concept of its own), this binding's `endpoint` is a full `wss://` URL
  — the daemon's existing HTTP path-routing mux is what dispatches to
  the handshake handler, so the endpoint needs a path, exactly like
  `inbox` is a full URL rather than a bare host:port.
- Absence means this binding is not offered; unknown `proto` values
  (this one, from the perspective of an implementation that predates
  this document) MUST be ignored, per `awp-quic-v0.1.md` §2's rule,
  extended verbatim to any future transport token.
- Inside the signed index: attributable and downgrade-resistant for the
  same reason `transports` already is (core §0.1).

## 3. Framing

Each WebSocket message (RFC 6455 §5.6, either a text or binary frame,
whichever the sender chooses — receivers MUST accept both) carries
exactly one JSON payload:

| Message | Direction | Payload |
|---|---|---|
| `envelope` | sender → receiver | The envelope, verbatim per core §2.1 — same bytes that would POST to the HTTPS inbox. |
| `status` | receiver → sender | `{ "id": "envelope-ulid", "status": 202, "error": null }` |

`status.status` reuses the HTTPS gate codes verbatim
(`400/410/401/200/202/503`), identically to `awp-quic-v0.1.md` §3 — one
mapping, shared prose, zero new semantics per transport.

Max payload: the core §2.1 envelope cap (256 KiB), matching
`awp-quic-v0.1.md` §3's `MaxFrameSize`. A frame whose RFC 6455 payload
length exceeds this is a connection error (receivers close the
connection with close code 1009, "message too big," rather than
attempting to buffer or reject-and-continue).

## 4. Connection model

- **One WebSocket connection carries many envelopes, correlated by
  `id`.** Unlike `awp/1`, which opens one QUIC stream per envelope
  (§4's "each envelope uses one bidirectional stream"), a WebSocket
  connection is a single ordered byte stream with no independent
  sub-streams — so responses are matched to requests by the envelope
  `id` already present in every `status` message, not by connection
  structure. A sender MAY have multiple envelopes in flight on one
  connection; a receiver processes them through the gate (§5) as they
  arrive and replies with `status` messages in the order it finishes
  them, not necessarily the order they arrived in (the gate's own
  ordering guarantees, if any, are unrelated to this transport).
- Connections are long-lived and SHOULD be reused across envelopes and
  threads, exactly as `awp-quic-v0.1.md` §4 recommends for QUIC — this
  is the entire reason either transport exists over plain HTTPS.
- **Ping/pong keepalive is out of scope for v0.1.** Idle-connection
  timeout policy (load balancers commonly close idle TCP after 60s) is
  an operational concern for a deployment's own reverse-proxy
  configuration, not something this binding standardizes; a sender
  whose connection was closed by an intermediary simply redials on its
  next send, identically to `awp-quic-v0.1.md` §4's "idle timeout is
  the implementation's choice."
- Close: either side MAY send a Close frame (opcode 0x8) at any time; a
  receiver that sees Close simply stops serving that connection — any
  envelope whose `status` hadn't been sent yet is, from the sender's
  point of view, unacked and falls into the normal retry path (§5),
  identical to a QUIC stream reset.

## 5. Equivalence and fallback

1. **Gate equivalence.** The receiver MUST apply the identical core §2.2
   gate, in order, with identical outcomes, regardless of transport —
   `internal/wstrans`'s server handler calls the same transport-blind
   `inbox.Gate.Accept` that the HTTPS and `awp/1` adapters call (CLAUDE.md's
   own stated invariant: "internal/inbox exposes a transport-blind Gate
   interface; HTTP and QUIC are thin adapters over it" — this binding is
   a third thin adapter over the same interface, not a fourth
   implementation of the gate's logic).
2. **Fallback.** On WebSocket handshake failure, connection error, or
   absent advertisement, senders MUST fall back per this reference
   ordering: WebSocket → `awp/1` (if advertised) → HTTPS, for the exact
   same envelope bytes and `id`. As with QUIC (`awp-quic-v0.1.md` §5
   rule 2), the outbox state machine treats transport selection as an
   attempt detail, not a state: a failed WebSocket attempt and a failed
   HTTPS attempt are the same `queued`-with-backoff transition.
3. **Dedupe across transports** is automatic and three-way — one `seen`
   store, keyed by `id`, transport-blind, shared by HTTPS, `awp/1`, and
   this binding alike.

## 6. Security considerations

- No downgrade surface: `wss://` terminates in the same signed-envelope
  model as HTTPS and `awp/1`; transport choice never changes
  authentication, exactly as `awp-quic-v0.1.md` §7 states for QUIC.
- Masking: per RFC 6455 §5.3, client-to-server frames MUST be masked;
  server-to-client frames MUST NOT be. This is RFC 6455's own anti-cache-
  poisoning mitigation for intermediaries that don't understand
  WebSocket framing, not an AWP-specific requirement — implementations
  simply follow RFC 6455 here.
- Origin header: this binding has no browser client in its threat model
  (senders are other AWP daemons, not scripts running in a browser
  context), so `Origin` validation — RFC 6455's mitigation for
  browser-originated cross-site WebSocket abuse — is not meaningful here
  and this document takes no position on it; a receiver MAY still check
  it defensively at no protocol cost.

## 7. Conformance (`awp-ws/1` endpoint)

1. Advertises via signed index `transports` with `proto: "awp-ws/1"`
   and a `wss://` endpoint.
2. Completes the RFC 6455 handshake and responds with a correct
   `Sec-WebSocket-Accept`.
3. Identical gate outcomes to its own HTTPS inbox for identical
   envelopes.
4. Handles ≥ 100 concurrent envelopes multiplexed on one connection
   (§4), not merely ≥ 100 concurrent connections.
5. Survives sender fallback: an envelope delivered over HTTPS (or
   `awp/1`) after a failed WebSocket attempt is deduped, not double-
   processed.
