# AWP-QUIC v0.1 — `awp/1` Transport Binding

**Status:** draft. Optional transport for **envelope delivery only**. HTTPS
remains the mandatory floor (core §6): every implementation MUST speak the
HTTPS inbox; `awp/1` is a negotiated upgrade. Sync tool calls are HTTPS-only
in v0.1 — RFC 9421 is HTTP-native and this binding deliberately does not
re-specify request signing outside HTTP.

## 1. Connection

- QUIC v1 (RFC 9000), TLS 1.3 as built into QUIC.
- ALPN: `awp/1`. Anything else on the connection is a protocol error.
- SNI = the receiving domain; certificate validated against WebPKI exactly as
  HTTPS — same trust root, no new PKI (consistent with L0).
- Default port: the one advertised (§2); no IANA default assumed in v0.1.
- **0-RTT is permitted for envelope frames.** Safe by construction: envelope
  `id` dedupe (core §2.2 gate 4) makes delivery idempotent, so QUIC replay
  collapses into the already-handled duplicate case. Receivers apply the
  identical gate to 0-RTT and 1-RTT data.

## 2. Advertisement

Domain index (core §1.1) gains an OPTIONAL field:

```json
"transports": [
  { "proto": "awp/1", "endpoint": "example.com:8443" }
]
```

- Absence means HTTPS-only. Unknown `proto` values MUST be ignored.
- The field is inside the signed index, so transport advertisement is
  attributable and downgrade-resistant: a MITM cannot *add* a bogus endpoint,
  and stripping the field only forces HTTPS — which is not a security
  downgrade, just the floor.

## 3. Framing

All frames: 4-byte big-endian length prefix + UTF-8 JSON payload.
Max payload 256 KiB (the core envelope cap); oversized frames are a
connection error.

| Frame | Direction | Payload |
|---|---|---|
| `envelope` | sender → receiver | The envelope, verbatim per core §2.1 — same bytes that would POST to the HTTPS inbox. |
| `status` | receiver → sender | `{ "id": "envelope-ulid", "status": 202, "error": null }` |

`status.status` reuses the HTTPS gate codes verbatim: `400/410/401/200/202/503`
with identical semantics (core §2.2). `error`, when present, is the core §2.6
error object. One mapping, zero new semantics.

## 4. Stream model

- Each envelope uses one **bidirectional stream**: sender opens, writes one
  `envelope` frame, half-closes; receiver runs the gate, writes one `status`
  frame, closes. Stream done.
- Concurrent envelopes = concurrent streams; QUIC removes head-of-line
  blocking between them — the reason this binding exists.
- Connections are long-lived and SHOULD be reused across envelopes and
  threads. Idle timeout is the implementation's choice; senders MUST handle
  server-initiated close gracefully (envelopes in flight on reset streams
  are simply unacked → normal retry path).

## 5. Equivalence and fallback

1. **Gate equivalence.** The receiver MUST apply the identical §2.2 gate,
   in order, with identical outcomes, regardless of transport. An envelope's
   fate cannot depend on how it arrived.
2. **Fallback.** On QUIC connection failure, timeout, or absent
   advertisement, senders MUST fall back to the HTTPS inbox for the same
   envelope (same bytes, same `id`). The outbox state machine
   (`awpd-outbox`) treats transport selection as an attempt detail, not a
   state: a failed QUIC attempt and a failed HTTPS attempt are the same
   `queued`-with-backoff transition.
3. **Dedupe across transports** is automatic — one `seen` store, keyed by
   `id`, transport-blind.

## 6. The `awp://` scheme

Addressing, not plumbing (core §6). Syntax:

```abnf
awp-uri = "awp://" principal            ; principal per core §0 grammar
```

`awp://invoicer.example.com#generate` identifies an entity; resolution is
always: DNS → `/.well-known/awp.json` (HTTPS) → manifest → transport
selection per §2/§5. The scheme never implies QUIC — it implies AWP
resolution. Clients encountering `awp://` URIs in documents, manifests, or
envelope bodies resolve them exactly as bare principal names.

## 7. Security considerations

- No downgrade surface: HTTPS is the floor, not a fallback *from* something
  stronger; both transports terminate in the same signed-envelope model, so
  transport choice never changes authentication.
- 0-RTT replay: handled by envelope dedupe (§1). Receivers MUST NOT process
  0-RTT envelope frames ahead of the dedupe check.
- Amplification: receivers MUST NOT send `status` frames larger than the
  received envelope frame (trivially true given the schema) and follow QUIC
  anti-amplification limits during the handshake.

## 8. Conformance (awp/1 endpoint)

1. Advertises via signed index `transports`.
2. ALPN `awp/1`, WebPKI cert for the domain.
3. Identical gate outcomes to its own HTTPS inbox for identical envelopes.
4. Handles ≥ 100 concurrent envelope streams.
5. Survives sender fallback: an envelope delivered over HTTPS after a failed
   QUIC attempt is deduped, not double-processed.
