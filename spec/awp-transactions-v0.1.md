# AWP-Transactions v0.1 — Multi-Tool Saga Coordination

**Status:** draft. One additive extension to the entity manifest (core
§1.2) and one sync-call header (`awp-sig-v0.1.md`), plus a documented
(non-wire) coordinator algorithm. This is the roadmap's highest-risk item
— read §0 before anything else.

## 0. What this document does not do

**AWP has no distributed transaction coordinator, and this document does
not add one.** Two-phase commit (or any protocol requiring a prepare/lock
step across parties) needs every participant to trust a shared
coordinator with a lock on their own state for the duration of the
transaction. AWP's participants are independently operated domains with
no prior trust relationship beyond "both speak AWP" — there is no escrow,
no shared clock, and (core §6) no transport-level primitive that could
carry a distributed lock protocol even if one were designed. Attempting
real cross-domain ACID atomicity here would be dishonest: it would either
silently assume a trust relationship AWP doesn't have, or require every
tool provider to implement a prepare/commit/abort state machine most will
never build correctly.

What this document provides instead is the **saga pattern**: a caller
calls a sequence of independent tools; if a later step fails, the caller
calls each already-succeeded step's declared **compensating action**, in
reverse order. This is eventual consistency via compensation, not
atomicity. It is also the only pattern that has ever actually worked at
this trust boundary — it's what every microservice architecture and every
cross-company payment/booking integration in production already does,
under names like "saga" or "compensating transaction." AWP's contribution
is standardizing the three small pieces every ad-hoc implementation of
this pattern reinvents: how a tool advertises its own undo, how a caller
tags a call as part of a numbered sequence, and what a participant may
assume about retried compensations.

A transaction whose every step happens to share one domain MAY be
implemented by that operator as a real internal database transaction —
AWP has no way to know or care, since from the wire it's still just a
sequence of tool calls (§4 notes this explicitly).

## 1. Manifest `compensated_by` (entity-level)

Entity manifest (core §1.2) gains an OPTIONAL field:

```json
"compensated_by": "example.com#cancel-reservation"
```

- A principal naming the tool that undoes this one's effect, if any. A
  coordinator that needs to unwind a transaction looks this field up on
  the manifest of the tool it already called — it never needs a
  separate reverse-lookup registry.
- Absence means this tool declares no compensating action. A coordinator
  that includes a step with no `compensated_by` in a transaction it cares
  about atomicity for is accepting that step as **irreversible**: if a
  later step fails, that effect stands. This is the caller's judgment
  call, not something this document can prevent — an irreversible step
  (e.g. sending an email) simply cannot be compensated, ever, by any
  protocol.
- The compensating tool itself is an ordinary manifest, published and
  called exactly like any other tool. It MAY itself declare a
  `compensated_by` (compensating the compensation), though that is
  unusual and this document takes no position on it.
- Like every other manifest field, `compensated_by` is inside the signed
  document — a caller cannot be tricked into calling an attacker-chosen
  "undo" action by anything short of forging the manifest's signature.

## 2. The `AWP-Transaction` header

A sync call (`awp-sig-v0.1.md`) MAY carry:

```
AWP-Transaction: base64url(JSON({"id": "01h...", "step": 0, "coordinator": "caller.example.com"}))
```

- `id`: a ULID minted once by the coordinator, shared by every call
  (forward or compensating) belonging to one transaction attempt.
- `step`: a 0-indexed integer, the position of this call in the
  coordinator's sequence. Compensating calls SHOULD reuse the same `step`
  value as the forward call they are undoing — `(id, step)` identifies
  "this logical unit of work," not "this specific HTTP request."
- `coordinator`: the principal driving the transaction, for the
  participant's own logging/observability. Not cryptographically bound
  to anything beyond ordinary request signing (the request is already
  signed by the calling principal per `awp-sig`; `coordinator` is
  informational, not a second authentication factor).
- This is an ordinary `AWP-*` header: `internal/httpsig`'s existing
  `CoveredComponents` rule already covers it automatically, exactly as
  `awp-capabilities-v0.1.md` §3.1 designed `AWP-Dry-Run` to work — **no
  change to the signing or verification algorithm is needed.**
- `AWP-Transaction` is advisory, like `AWP-Dry-Run`: a tool that never
  reads it executes normally, forward or compensating call alike — this
  document places no gating requirement on it. A malformed header (bad
  base64url, bad JSON, missing required field) is a request-level
  `malformed` error (core §2.6), since a caller that sends the header at
  all is claiming a shape it must actually honor — unlike `AWP-Dry-Run`,
  which is a single boolean with no invalid non-empty state.

### 2.1 Idempotency

Compensating calls MAY be retried by the coordinator after a network
failure — the coordinator cannot tell "compensation didn't happen" apart
from "compensation happened but the response was lost." A tool that
declares `compensated_by` on itself, or that IS a `compensated_by` target
for another tool, SHOULD treat `(id, step)` as a dedupe key using its own
state (a session lookup, a local ledger — implementation-specific,
exactly as general tool-side idempotency already is everywhere else in
this spec) and return the same result for a repeated `(id, step)` rather
than compensating twice. This document does not, and cannot, enforce this
from outside — it is a SHOULD on the participant, like `AWP-Dry-Run`'s
no-side-effect obligation (`awp-capabilities-v0.1.md` §4.2).

## 3. Coordinator algorithm (non-normative, caller-side)

This is not a wire primitive — no daemon needs to implement this section
to be conformant. It is the pattern `AWP-Transaction` and
`compensated_by` exist to support, written down once so every
implementation doesn't reinvent it slightly differently:

```
txn_id := new_ulid()
completed := []          # steps that succeeded, in order
for step, call in enumerate(sequence):
    result := invoke(call.tool, call.input,
                      AWP-Transaction={id: txn_id, step: step, coordinator: self})
    if result is error:
        for prior_step, prior_call, prior_result in reversed(completed):
            undo := fetch_manifest(prior_call.tool).compensated_by
            if undo is not None:
                invoke(undo, compensation_input(prior_call, prior_result),
                       AWP-Transaction={id: txn_id, step: prior_step, coordinator: self})
            # else: prior_step is irreversible; its effect stands (§0)
        raise TransactionAborted(failed_at=step, cause=result.error)
    completed.append((step, call, result))
return completed
```

- `compensation_input` is application-specific — this document does not
  standardize how a compensating tool's input is derived from the
  forward call's input/output (e.g. "cancel-reservation" plausibly needs
  the confirmation ID the forward call returned). A tool declaring
  `compensated_by` SHOULD document, in its own `description` (core
  §1.2's normative interface surface), what its compensating tool
  expects as input.
- The coordinator's own crash mid-sequence is a real failure mode this
  algorithm does not solve: a coordinator that dies after step 2 succeeds
  but before compensating it leaves that effect permanently uncompensated
  unless the coordinator persists `completed` somewhere durable and
  resumes on restart — exactly the same durability obligation
  `awpd-outbox-v0.1.md` already places on outbound envelope delivery, and
  for the same reason (state that matters must survive a crash, not live
  only in memory).

## 4. Same-domain optimization

Nothing in this document prevents an operator whose transaction steps all
happen to be entities of one domain from implementing true atomicity
internally (one database transaction spanning all of them) instead of
running the saga algorithm at all. From the wire's perspective this is
indistinguishable from an unusually reliable saga — `AWP-Transaction` and
`compensated_by` are unnecessary in this case (there is nothing to
compensate if the domain's own internal commit already guarantees
all-or-nothing), but harmless to include anyway if a caller's code path
doesn't distinguish same-domain from cross-domain sequences.

## 5. Conformance

1. `compensated_by`, when present, is inside the signed manifest and
   rejects verification if tampered — implied by core §0.1, not a new
   check.
2. `AWP-Transaction`, when present and malformed, MUST be rejected with a
   `malformed` error (§2) — a conformance run MAY probe this with a
   deliberately corrupt header value.
3. No conformance check can verify that a tool's compensating action
   actually undoes the forward action's effect, or that `(id, step)`
   dedup (§2.1) is actually implemented — both are unobservable from
   outside, like `awp-capabilities-v0.1.md` §4.2's dry-run no-side-effect
   claim. A conformance run MAY only check that a declared
   `compensated_by` principal resolves to a real, callable entity.
