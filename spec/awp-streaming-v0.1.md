# AWP-Streaming v0.1 — Chunked Response Bodies

**Status:** draft. Optional extension to Part 2 (async envelopes) of
`awp-core-v0.1.md`. Applies only to async agent-to-agent communication;
§7 explains why sync tool calls (`awp-sig-v0.1.md`) are explicitly out of
scope rather than extended.

## 1. Motivation

AWP has no streaming primitive prior to this document — not even a
deferred one (`awp-core-v0.1.md` §7's v0.2 backlog doesn't mention it).
The reason is real, not an oversight: `awp-sig` signs one complete
message atomically, and core §0.1's signature construction is defined
over one complete canonicalized object. Content that's produced
incrementally (token-by-token model output, a long-running computation
reporting progress) has nowhere to go in that model without either
signing fragments separately or leaving fragments unauthenticated until
a final signed message closes the stream.

This document chooses the former, and changes nothing about how
signatures work to do it: a "stream" is simply several ordinary,
independently and fully signed envelopes. No change to the envelope
schema (core §2.1), no change to signature construction (core §0.1), no
change to the receiver gate (core §2.2). This is a body-type extension
only (core §2.3: "`body.type` is an open set").

## 2. The `stream_chunk` body type

```json
{
  "type": "stream_chunk",
  "stream_id": "01j3z9k4x2m4q5r6s7t8u9v0w1",
  "seq": 3,
  "final": false,
  "data": { "text": "...next chunk of content..." }
}
```

| Field | Rules |
|---|---|
| `stream_id` | ULID (core §0), minted by the sender of `seq: 0` for this stream. Identifies which stream a chunk belongs to, scoped to the thread it's carried on. |
| `seq` | Integer, zero-based, strictly increasing per `stream_id`. REQUIRED — see §4 for why. |
| `final` | Boolean. `true` on exactly one chunk: the last one. See §5. |
| `data` | Application-defined content for this chunk. Opaque to this document. |

Every chunk travels as an ordinary envelope. `in_reply_to` on every chunk
MUST reference the original request envelope's `id` — chunks are
siblings answering one request, not a chain answering each other.
`kind` is whatever the response would have been without streaming
(typically `reply`); this document does not introduce a new envelope
`kind`.

## 3. Signing (unchanged)

Each chunk envelope MUST be signed per core §0.1, independently, exactly
like any other envelope. There is no partial-trust mode: a receiver MUST
verify every chunk's signature before accepting it into the reassembly
buffer (§4), identically to how any other inbound envelope is verified
at core §2.2 gate 3. A stream is only as trustworthy as its
least-verified chunk would be if that check were skipped — which is why
this document does not permit skipping it.

## 4. Ordering and reassembly

Delivery order is not guaranteed even for chunks of the same stream:
`awpd-outbox-v0.1.md`'s retry/backoff behavior can reorder deliveries
relative to send order, and core §2.4 already establishes that receivers
"MUST NOT reject solely for out-of-order arrival" for ordinary envelopes.
The same tolerance applies here, which is why `seq` is mandatory rather
than relying on arrival order or envelope `id` (a ULID's embedded
timestamp reflects send time, not a guarantee of delivery order).

A receiver:

1. MUST buffer verified chunks for a `(thread, stream_id)` pair, keyed by
   `seq`, until reassembly is complete or the stream times out (§5).
2. MUST NOT deliver partial content to the application layer out of
   order — chunk `seq: 2` is not delivered before `seq: 0` and `seq: 1`
   have arrived, even if `seq: 2` was received first.
3. MAY deliver each chunk to the application layer incrementally, in
   order, as gaps are filled — this document does not mandate
   "buffer everything, then deliver once," only in-order delivery.

There is no retransmission-request primitive in this document. A missing
`seq` is a gap the receiver waits out, bounded by each chunk's own `ttl`
(core §2.1) — not something the receiver can ask the sender to resend
out of band.

## 5. Termination

The chunk with `final: true` ends the *stream*. It does not end the
*thread* — `close` (core §2.4) is unaffected and continues to mean what
it already means. A receiver that has seen every `seq` from `0` through
the `final` chunk's `seq`, with no gaps, MUST treat the stream as
complete.

A stream that never receives a `final: true` chunk (sender crashed,
network partition) MUST be treated as failed once every already-received
chunk's `ttl` has elapsed with the gap unfilled. This document does not
define a wire-visible "stream aborted" signal; detecting an incomplete
stream is a receiver-local concern, bounded by the same TTL mechanism
that already bounds every envelope.

## 6. Bounds

Alongside the existing 256 KiB per-envelope cap (core §2.1) and the
8-link delegation chain cap (core §2.5 rule 6): a receiver MUST NOT
buffer more than **65536** chunks for a single `stream_id`. A stream
that exceeds this MUST be rejected with `error(refused)` (core §2.4's
registry), and the receiver MUST discard its reassembly buffer for that
`stream_id`. This is a fixed constant, not a configurable value — core's
existing bounds are fixed for the same reason (`awp-sig`'s own framing:
"one fewer knob to misconfigure").

## 7. Chunking granularity (SHOULD, not MUST)

Senders SHOULD coalesce content to a reasonable granularity — sentences,
paragraphs, or a bounded time window — not one chunk per token of
model output. Each chunk carries the full cost of an independent
envelope: headers, one Ed25519 signature, one HTTP round trip if not
otherwise batched. The cryptographic cost itself is cheap
(sub-millisecond Ed25519 verification); the fixed per-envelope overhead
is what makes token-level chunking wasteful, not the signing.

## 8. Sync tool calls are explicitly out of scope

A `distribution.hosted` tool call (`awp-sig-v0.1.md`) that wants to
stream its response MUST NOT be extended with any of the above. Two
options were considered for sync streaming; this document adopts
neither, in favor of routing streaming sync-shaped work through the
mechanism above instead:

- **Rejected: HTTP-native chunked transfer with a hash-commitment
  manifest.** Sign a Merkle-style list of chunk hashes once, upfront;
  verify each streamed chunk against it as it arrives. Technically
  workable, but requires a new signing primitive — in real tension with
  `awp-sig`'s explicit "no negotiation, no algorithm agility" design and
  closer in scope to a v2 protocol feature than a v0.1 extension.
- **Adopted: model streaming sync work as async instead.** A caller that
  wants a streamed answer sends a `task` body (core §2.3, already
  registered) to a `kind: agent` entity instead of a `kind: tool` sync
  call, and receives the answer as the `stream_chunk` sequence defined
  above. One streaming mechanism total; `awp-sig` and hosted sync calls
  are unchanged by this document.

## 9. Backward compatibility

An implementation that has not adopted this document already has
correct, defined behavior on receiving a `stream_chunk` body: core
§2.3's existing rule ("Unknown body types MUST produce an error envelope
— `code: unsupported_body` — never a silent drop") applies unchanged. No
protocol version bump is required to introduce this extension, and no
implementation is broken by another implementation adopting it.

## 10. Conformance (implementations claiming streaming support)

1. Every chunk's signature is independently verified before it enters
   the reassembly buffer (§3) — never accepted on the strength of the
   stream's `final` chunk alone.
2. Out-of-order chunk delivery is tolerated and correctly reassembled by
   `seq` (§4).
3. A stream is not delivered to the application layer with a gap in
   `seq`, regardless of how long the gap persists short of TTL expiry.
4. The §6 bound is enforced, and exceeding it produces `error(refused)`,
   not unbounded buffering.
5. An implementation that has *not* adopted this document rejects a
   `stream_chunk` body with `error(unsupported_body)`, per §9 — checked
   against the reference implementation, not just asserted.
