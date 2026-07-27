# AWP-Push v0.1 — Wake-Notification Hint

**Status:** draft. One small, purely additive extension to the domain
index (core §1.1). This is a liveness *hint*, not a transport: envelope
bytes always travel over the same HTTPS inbox POST (core §2.2,
`awpd-outbox-v0.1.md`) they always did. Comparable in spirit to
`awp-quic-v0.1.md`'s `transports[]` entry, but `wake` never carries
envelope content — it only tells a sender "try me again now" sooner than
backoff otherwise would.

## 1. Why this exists

`awpd-outbox-v0.1.md`'s retry loop is polling-shaped from the sender's
side: full-jitter backoff, capped, until the receiver responds. That's
correct for an always-up HTTPS listener, but some receivers (a
serverless function, a mobile app, a process that scales to zero) are not
always listening. Without some out-of-band nudge, such a receiver only
gets its queued mail on the sender's next backoff tick — which may be
minutes away by the time it wakes back up on its own.

## 2. Index `wake` (domain-level)

Domain index (core §1.1) gains an OPTIONAL field:

```json
"wake": { "endpoint": "https://example.com/awp/wake" }
```

- `endpoint` is a URL a sender MAY `POST` to, with an empty body and no
  signature, when it has just failed to deliver to this domain's `inbox`
  because of a network error or a `5xx` response (§3 says exactly when).
- This field lives inside the signed index — attributable and
  downgrade-resistant for the same reason `transports` and `capabilities`
  are (core §0.1's signature covers the whole document minus `sig`).
- Absence means "no wake hint available" — senders fall back to ordinary
  backoff-only retry, exactly as if this document did not exist.

## 3. Sender behavior

A sender implementing this document MAY, after a delivery attempt to
`inbox` that results in `awpd-outbox-v0.1.md`'s `retry` transition **via
a network error or a `5xx` response**, additionally `POST` an empty body
to `wake.endpoint`, best-effort:

- **Never** on `2xx` (delivered — nothing to wake).
- **Never** on a `429` whose `Retry-After` was honored — a `429` response
  proves the receiver is alive and reachable; it asked for patience, not
  a wake.
- **Never** on `dead` transitions (`4xx` other than `429`, or pre-attempt
  TTL expiry) — the envelope is not retryable regardless of whether the
  receiver wakes up.
- The wake `POST`'s outcome (status, timeout, connection failure) MUST
  NOT influence the outbox state machine in any way — it is fired best-
  effort, its result discarded, and normal backoff-and-retry against
  `inbox` continues exactly as it would if `wake` did not exist. A sender
  MUST NOT treat a successful wake `POST` as delivery, and MUST NOT skip
  or delay the next scheduled `inbox` retry because of it.
- A sender SHOULD bound how long it waits on the wake `POST` (it must
  never block or slow down the outbox's own attempt loop) and MAY drop
  the connection entirely without waiting for a response.

## 4. Receiver behavior

- `wake.endpoint` carries **no envelope content and no signature** — it
  authorizes nothing and reveals nothing about which sender is calling it
  or what mail is waiting. A receiver MUST NOT gate any privileged
  action on a `wake` request; its only legitimate effect is "maybe check
  `inbox`-bound work sooner."
- Because it is unauthenticated by design, `wake.endpoint` is a public
  URL knowable by anyone who reads the index. Receivers SHOULD rate-limit
  it cheaply (it does nothing but possibly resume a suspended process) —
  this document does not standardize a rate-limiting mechanism.
- A receiver declaring `wake` MUST still serve a real, directly-reachable
  `inbox` per core §1.1 rule 1 — `wake` supplements delivery, it never
  replaces the obligation to actually receive envelopes over HTTPS.
- The wake `POST`'s response body, if any, is ignored by senders (§3);
  receivers MAY return any `2xx` and SHOULD avoid leaking information in
  it (it is reachable by anyone).

## 5. Conformance

1. `wake`, when present, is inside the signed index and rejects
   verification if tampered — implied by core §0.1, not a new check.
2. A conformance run MAY check that `wake.endpoint`, if declared, accepts
   an empty `POST` with some `2xx`/`4xx`/`5xx` response without hanging —
   this is a reachability smoke test, not a claim about whether wake
   notifications actually cause anything to happen (unobservable from
   outside, like `awp-capabilities-v0.1.md` §4's dry-run no-side-effect
   claim).
3. Nothing about this document changes core §2.2's gate order or
   `awpd-outbox-v0.1.md`'s state machine — `wake` is an additional,
   ignorable side effect of the existing `retry` transition, not a new
   state.
