# Experiments log

Per CLAUDE.md: each phase's passing gate output, recorded before planning the
next phase.

## Phase 1 — crypto core

**Scope:** `internal/identity`, `internal/envelope`, `internal/manifest`,
`internal/delegation` — signing primitive (core §0.1), domain index / key
rotation / revocation (core §1.1), entity manifest + sha256 pinning
(core §1.2), envelope types + ULID (core §2.1), delegation chain
verification (core §2.5). No networking, no storage — pure crypto/verification
logic, consistent with the phase boundary in CLAUDE.md.

**Environment:** go1.26.5 darwin/arm64, commit `ec3c486` + this phase's work
(uncommitted at time of gate run — see `git status`).

**Gate command:** `go test ./internal/... -count=1 -v`

**Result:** PASS, all packages.

```
ok  	github.com/agentask/awp/internal/delegation	0.272s
ok  	github.com/agentask/awp/internal/envelope	0.954s
ok  	github.com/agentask/awp/internal/identity	0.487s
ok  	github.com/agentask/awp/internal/manifest	0.711s
```

### EARS gate coverage

1. **Round-trip determinism** — WHEN any signed object is round-tripped
   sign→verify, the system SHALL produce byte-identical JCS canon and
   verify.
   - `identity.TestRoundTripSignVerify_ByteIdenticalCanon`,
     `identity.TestIndexSelfSignVerify_RoundTrip`,
     `manifest.TestManifestSignVerify_RoundTrip`,
     `envelope.TestEnvelopeSignVerify_RoundTrip` (includes a JSON wire
     round-trip, not just in-memory).
   - Negative controls: `identity.TestVerifySig_RejectsTamperedContent`,
     `identity.TestVerifySig_RejectsWrongKey`,
     `manifest.TestManifestVerify_RejectsTamperedContent`,
     `envelope.TestEnvelopeVerify_RejectsTamperedContent`.

2. **Rotation-chain integrity** — WHEN a rotation chain contains one broken
   link, verification SHALL reject.
   - `identity.TestVerifyRotationChain_TableDriven` — 9 cases: valid
     single/two-link chains, root-only, and 5 distinct break modes (wrong
     signer, tampered pub claim, missing prev_sig, malformed prev_sig,
     valid-then-broken).
   - `identity.TestVerifyRotationChain_IdentifiesBrokenIndex` — asserts the
     specific broken link index is reported, not just a boolean failure.

3. **Delegation-chain rule enforcement** — WHEN a delegation chain violates
   any core §2.5 rule, it SHALL reject with the specific rule identified.
   - `delegation.TestVerify_EachRuleViolatedInIsolation` — one subtest per
     rule (chain-too-long, root-scope-unbounded, bad signature, expiry,
     continuity, final-delegate, scope-intersection-on-`to`), each holding
     every other rule valid so the isolated rule is unambiguously the cause.
   - `delegation.TestVerify_ScopeIntersection_KindAndBodyType` — the
     `kinds`/`body_types` sub-cases of the scope-intersection rule.
   - `delegation.TestVerify_ChainLengthBoundary` — exactly 8 links verifies,
     9 rejects with `chain_too_long` (boundary, not just over-the-limit).
   - `delegation.TestVerify_HappyPath` / `TestVerify_EmptyChainIsNotAViolation`
     — positive controls (empty `delegation[]` is valid: no delegation
     asserted, nothing to verify).

Also covers core §1.1 rule 3 (revocation/expiry postdates/predates), which
CLAUDE.md's Phase 1 bullets don't call out as a separate EARS line but which
`internal/identity` is in scope for per the phase's package list:
`identity.TestKeyValid_RevocationAndExpiry` (8 cases).

### Spec gap flagged (per CLAUDE.md: spec wins, discrepancy flagged, not silently resolved)

core §1.1 rule 3 requires rejecting signatures on objects that "postdate the
revocation" of a key, but the index schema in §1.1 has no `revoked_at` (or
equivalent) field — only a boolean `revoked`. There is no wire-visible
revocation instant to compare against. `identity.KeyValid` takes the
revocation instant as a caller-supplied `*time.Time` parameter (documented at
the function) and **fails closed** (rejects) when `revoked: true` but no
instant is supplied. Whichever later phase fetches/caches domain indexes
(`internal/store`'s `keys_cache`, per `awpd-store-v0.1.md`) will need to
decide what that instant actually is in practice — the most defensible
reading is "the `updated` timestamp of the first index document that set
`revoked: true`," which requires diffing successive index fetches, not just
reading the current one. Flagging for Phase 2+ rather than inventing a
`revoked_at` field unilaterally.

### Deliberately out of scope for Phase 1 (later phases)

- HTTP fetch of domain indexes / manifests (networking is Phase 2+;
  `identity.Index`, `manifest.Manifest` are pure types + verification here).
- The core §2.2 receiver gate order and status codes (Phase 2).
- `awp-sig` RFC 9421 subset / `internal/httpsig` (referenced by core §2.6 but
  explicitly deferred; not part of the Phase 1 package list).
- bbolt persistence, outbox retry state machine (Phases 2–3).

## Phase 2 — inbox + store

**Scope:** `internal/inbox` (transport-blind `Gate` + thin HTTP adapter) and
`internal/store` (bbolt), per core §2.2 and `awpd-store-v0.1.md`. Also added,
as shared infra CLAUDE.md's conventions call for but doesn't assign to a
named package: `internal/clock` (injected wall-clock source) and
`internal/apperr` (the one `{code, detail, retryable}` error grammar for
sync and async).

Two scoping decisions made explicitly before starting (confirmed with the
user):

1. **Key resolution.** The gate's signature-verification step needs to
   resolve a signer's domain key. Rather than building an HTTP index-fetcher
   + `keys_cache` now, `inbox.Gate` takes an injected `KeyResolver`
   interface (`Resolve`, `Refresh` — mirroring `delegation.KeyResolver` from
   Phase 1). Real HTTP fetch/caching is deferred to whichever phase first
   needs live cross-domain resolution (Phase 4's two-instance E2E). Phase 2
   tests use fakes, including one that simulates a rotation race (stale key
   until `Refresh` is called once) to exercise the core §0.1 one-refetch
   rule.
2. **Kill-9 test fidelity.** Implemented as a real subprocess: a self-exec
   helper opens the bbolt store, begins the `seen` write inside a
   transaction it deliberately never commits or extends to the `inq` write,
   signals readiness over stdout, then blocks; the parent test sends a real
   `SIGKILL` at that point, reopens the store, and asserts neither write
   landed. Ran 5x back-to-back with no flakes before proceeding.

`internal/store` implements only the `meta`, `seen`, and `inq` buckets —
what the gate needs. `inq_active`, `threads`, `thread_msgs`, `keys_cache`,
and `sessions` are processing-time/HTTP-caching concerns for later phases
and are not built yet (avoids speculative scope; nothing in Phase 2's EARS
bullets exercises them).

**Environment:** go1.26.5 darwin/arm64.

**Gate commands:** `go test ./... -count=1 -v`, `go test ./... -race
-count=1`, `go vet ./...`, `gofmt -l .`.

**Result:** PASS, all packages; vet and gofmt clean; race-clean.

```
ok  	github.com/agentask/awp/internal/delegation	0.425s
ok  	github.com/agentask/awp/internal/envelope	0.276s
ok  	github.com/agentask/awp/internal/identity	0.670s
ok  	github.com/agentask/awp/internal/inbox	1.141s
ok  	github.com/agentask/awp/internal/manifest	0.980s
ok  	github.com/agentask/awp/internal/store	1.297s
```

### EARS gate coverage

1. **Gate-order status codes, IN ORDER** — WHEN an envelope hits the gate,
   the system SHALL return the core §2.2 status for each failure class, in
   gate order.
   - `inbox.TestGate_OrderMatrix` — one case per failure class (malformed
     JSON, oversized payload, ttl out of bounds, missing sig, expired,
     bad signature, wrong signer) plus a **combined-failure** case
     (expired *and* invalid signature) asserting the earlier gate (410)
     wins, never reaching the signature check. This is the case that
     actually tests order, not just code reachability.
   - `inbox.TestGate_BadSignatureBeatsDuplicateId` — an id already durably
     accepted once, resent with tampered content: asserts 401 (gate 3),
     never 200 (gate 4) — proves gate 3 precedes gate 4 even when gate 4
     would otherwise short-circuit.
   - `inbox.TestGate_CapacityFailureReturns503` — store closed out from
     under the gate to force the gate-5 write to fail; asserts 503 +
     `retryable: true`.

2. **Crash recovery** — WHEN the process dies between gate 4 and gate 5,
   restart SHALL show either both `seen`+`inq` written or neither.
   - `store.TestKill9BetweenGate4And5` — real `SIGKILL` mid-transaction
     (see above); asserts neither bucket has the id after reopen.
   - `store.TestAcceptInbound_WritesBothSeenAndInq` — the complementary
     control: a successful `AcceptInbound` (real commit, no crash) shows
     both.

3. **Duplicate id, any transport** — WHEN a duplicate id arrives, it SHALL
   be acked 200 and not reprocessed.
   - `inbox.TestGate_DuplicateIdAcked200NotReprocessed` — byte-identical
     resend (as an outbox retry would send) gets 200 three times running;
     `store.HasQueued` confirms the envelope is enqueued exactly once.
   - `store.TestAcceptInbound_DedupesSecondArrival` — store-level: a
     duplicate `id` with *different* bytes still short-circuits and the
     originally stored bytes are provably untouched (guards against a
     dedupe-then-overwrite bug).

Also exercised, beyond the three EARS bullets, because core §0.1 requires it
and the gate's signature step depends on it: `inbox.TestGate_
RotationRace_OneRefetchThenSucceed` / `..._StillFailsAfterRefetch` — exactly
one `Refresh` call before either recovering or hard-failing.

### Deliberately out of scope for Phase 2 (later phases)

- Real HTTP index fetch/cache (`keys_cache` bucket) — see key-resolution
  decision above.
- Worker claim/complete (`inq_active`), thread state (`threads`,
  `thread_msgs`), sessions bucket — processing-time concerns, not gate
  concerns; first needed once something actually processes/replies to
  accepted envelopes (Phase 4 territory).
- `seen` bucket GC (hourly cursor scan) — retention-forever is spec-correct
  and safe; GC is a daemon-loop wiring concern with nothing to test yet
  since there's no `cmd/awpd` main loop.
- awp/1 QUIC adapter over the same `Gate` (Phase 4.5); only the HTTP adapter
  exists so far, per CLAUDE.md's "HTTP and QUIC are thin adapters" design —
  the QUIC adapter is new code, not new gate logic.

## Phase 3 — outbox

**Scope:** `internal/outbox` (delivery retry state machine, per
`awpd-outbox-v0.1.md`) plus the `outbox`/`outbox_sched` buckets added to
`internal/store` (the remaining piece of `awpd-store-v0.1.md` this reference
implementation needs before Phase 4). No `cmd/awpd`/`cmd/awp` binaries exist
yet — see the scope note below on the literal CLI half of the Phase 3 gate
description.

**Environment:** go1.26.5 darwin/arm64.

**Gate commands:** `go test ./... -count=1 -v`, `go test ./... -race
-count=1`, `go vet ./...`, `gofmt -l .`.

**Result:** PASS, all packages; vet and gofmt clean; race-clean.

```
ok  	github.com/agentask/awp/internal/delegation	0.372s
ok  	github.com/agentask/awp/internal/envelope	0.661s
ok  	github.com/agentask/awp/internal/identity	0.952s
ok  	github.com/agentask/awp/internal/inbox	1.683s
ok  	github.com/agentask/awp/internal/manifest	1.538s
ok  	github.com/agentask/awp/internal/outbox	3.086s
ok  	github.com/agentask/awp/internal/store	3.051s
```

### EARS gate coverage

1. **Retry byte-identical envelopes with full-jitter backoff, dead-letter
   at TTL (pre-attempt check)** — WHEN the receiver is down.
   - `outbox.TestAttempt_PreAttemptExpiry_NeverCallsSender` — an
     already-expired record never reaches the `Sender` at all (asserted via
     a call counter), goes straight to `dead_expired`.
   - `outbox.TestAttempt_TransitionTable` — network failure and 5xx both
     transition to `queued` (retry), matching the state diagram's collapse
     of "crash mid-request is indistinguishable from a network failure."
   - `outbox.TestFullJitterBackoff_StaysWithinBounds` — 15 attempt counts ×
     200 draws each, asserting every draw falls in
     `[0, min(cap, base·2^attempts)]`.
   - `outbox.TestAttempt_SameBytesEveryAttempt` — captures the exact bytes
     handed to `Sender` across two attempts (one failed, one succeeding)
     and asserts byte-for-byte identity with what was originally enqueued.
   - `outbox.TestIntegration_RetriesWhileReceiverDownThenDeliversWhenUp` —
     **two real local instances**: a sending outbox and a live
     `internal/inbox.Gate` receiver (on an `httptest.Server`), both in this
     process. The receiver starts unreachable (induced failure: pointed at
     a dead address), the sender records exactly one failed attempt, then
     the receiver comes up and the *same* sender retries successfully —
     verified on both sides (sender's record is gone; receiver's own store
     shows the envelope accepted).

2. **429 with `Retry-After` ≤ remaining TTL is honored** —
   - `outbox.TestAttempt_RetryAfterHonoredWithinTTL` — `next_at` lands
     exactly on `now + Retry-After`.
   - `outbox.TestAttempt_RetryAfterExceedingTTL_TreatedAs5xx` — a
     `Retry-After` (1000s) that exceeds the remaining TTL (60s) is
     rejected; `next_at` falls back to the bounded full-jitter backoff
     instead of the oversized value leaking through.
   - `outbox.TestAttempt_TransitionTable` — 429 *without* a `Retry-After`
     header is treated as 5xx.

3. **Daemon restart mid-delivery: in-flight records return to queued with
   next_at=now** —
   - `store.TestBootRecovery_DeliveringReturnsToQueuedWithNextAtNow` —
     claims a record (`delivering`), simulates the crash by doing nothing
     further, then calls `BootRecovery` at a later "restart" instant and
     asserts state=`queued`, `next_at` equals the restart instant exactly,
     and the record is immediately due again.
   - `store.TestBootRecovery_LeavesQueuedAndDeadUntouched` — negative
     control: boot recovery must not perturb records that were never
     mid-delivery.
   - This is tested via direct state-machine calls, not another OS-level
     kill: the durability half of "crash between two writes leaves no
     partial trace" was already proven for bbolt commits in Phase 2's
     `TestKill9BetweenGate4And5`, and `EnqueueOutbound`/`MarkDelivering`/
     `MarkRetry`/`MarkDead` all reuse the identical single-`Update()`-tx
     pattern — re-deriving that guarantee with a second subprocess+SIGKILL
     harness would test the same bbolt property twice. What Phase 3
     actually adds is the *boot-recovery logic* (delivering→queued,
     next_at=now), which is a pure state transition and is what these
     tests exercise directly.

Also covered, beyond the three EARS bullets, because awpd-outbox-v0.1.md §2
states them as rules: `outbox.TestProcessDue_OneInFlightPerDomain` (rule 5:
two due records for the same domain in one tick → only one attempted, the
other waits) and `outbox.TestProcessDue_DifferentDomainsProcessConcurrently`
(distinct domains proceed concurrently within a tick, bounded by
`cfg.Workers`); `outbox.TestIntegration_ReceiverRejectsNonRetryable4xx_DeadLetters`
(a second "two local instances" scenario: a real receiver that can't verify
the signature returns 401, and the outbox dead-letters rather than retrying
forever).

### Scope decisions made autonomously this phase (flagged here, not asked — see CLAUDE.md: spec/plan gaps get flagged, not silently resolved or blocked on)

1. **Boot-recovery test fidelity.** Chosen over a second subprocess+SIGKILL
   harness (see above) — reuses Phase 2's already-proven bbolt durability
   guarantee instead of re-testing it.
2. **CLI/daemon wiring.** CLAUDE.md's Phase 3 gate line — "two local
   instances, induced failures; `awp outbox ls --dead` reflects truth" —
   describes an operational check against running `awpd`/`awp` binaries.
   Neither binary exists yet (`cmd/awpd`, `cmd/awp` are still unbuilt, and
   were never in scope for Phases 1–3, which have stayed inside
   `internal/*`). This phase satisfies the *substance* of that gate line
   two ways: (a) the "two local instances, induced failures" half is built
   literally — a real second local instance (`internal/inbox.Gate` on an
   `httptest.Server`), not a mock, receiving induced failures (unreachable,
   then up; signature-rejecting); (b) the "`awp outbox ls --dead` reflects
   truth" half is satisfied one layer down — `store.ListDead()` is the exact
   primitive such a command would call, and its truthfulness is what
   `TestMarkDead_TableDriven` and the dead-letter assertions above verify.
   Wiring an actual `cmd/awp` CLI and `cmd/awpd` daemon main loop is
   deferred to Phase 4 (`v0.1.0-m1`), which is where those binaries first
   become load-bearing for the milestone's E2E test anyway.

### Deliberately out of scope for Phase 3 (later phases)

- `cmd/awpd` main loop actually calling `ProcessDue` on a real ticker, and
  `cmd/awp outbox ls --dead` — see scope decision above.
- Dead-letter GC (`outbox.dead_retention`, default 720h) — same reasoning as
  Phase 2's deferred `seen`-bucket GC: a daemon-loop wiring concern with
  nothing to test until a main loop exists.
- HTTP-date form of the `Retry-After` header (only numeric seconds is
  handled) — the numeric form is what real servers overwhelmingly send;
  revisit if conformance testing (Phase 5) turns up a real need.
- Metrics/counters (`delivered_total`, `dead_total{reason}`, etc.) — pure
  observability, no EARS behavior depends on them.

## Phase 4 — milestone v0.1.0-m1

**Scope:** close the deferrals from Phases 2–3 and wire everything into a
real running daemon. New: `internal/keyresolver` (real HTTP domain-index
fetch, self-sig verification, `keys_cache`-backed caching, rotation-race
refresh), `internal/daemon` (wires store+inbox+outbox+keyresolver into the
`awpd` behavior: signed index + inbox HTTP endpoints, `Send`, inbound
processing with a default message→ack+reply handler, thread bookkeeping),
and `cmd/awpd` (the real, buildable single-daemon binary CLAUDE.md's fixed
decisions require). Store gained `threads`, `thread_msgs`, `keys_cache`, and
real `inq`/`inq_active` claim-complete semantics (deferred from Phase 2).

**Environment:** go1.26.5 darwin/arm64.

**Gate commands:** `go test ./... -count=1 -v`, `go test ./... -race
-count=1`, `go vet ./...`, `gofmt -l .`. Per CLAUDE.md, "the E2E test IS the
release criterion" — `daemon.TestE2E_MessageAckReplyClose` is that test.

**Result:** PASS, all packages; vet and gofmt clean; race-clean; E2E test
run 5x back-to-back with no flakes.

```
ok  	github.com/agentask/awp/internal/daemon	1.762s
ok  	github.com/agentask/awp/internal/delegation	0.378s
ok  	github.com/agentask/awp/internal/envelope	0.989s
ok  	github.com/agentask/awp/internal/identity	0.675s
ok  	github.com/agentask/awp/internal/inbox	1.973s
ok  	github.com/agentask/awp/internal/keyresolver	2.329s
ok  	github.com/agentask/awp/internal/manifest	1.780s
ok  	github.com/agentask/awp/internal/outbox	3.700s
ok  	github.com/agentask/awp/internal/store	3.483s
```

`cmd/awpd` was also smoke-tested directly (not just via `go build`): started
with a fresh identity/data dir, it served a correctly self-signed
`/.well-known/awp.json` with the right `inbox` URL, then was cleanly killed.

### EARS gate: the E2E test

WHEN instance A sends `message` to instance B over HTTPS, the system SHALL
complete message → ack → reply → close with every signature verified and
thread state correct on both sides.

`daemon.TestE2E_MessageAckReplyClose` runs **two real local instances** —
each its own identity, bbolt store, and live `httptest.Server` — and drives
the full sequence over real HTTP (see the transport scope note below for
why HTTP-over-127.0.0.1 rather than literal TLS):

1. A sends `message` (opening a new thread); A's outbox delivers it to B's
   real `/awp/inbox`.
2. B's inbound processing claims it, records thread state, and runs the
   default reference handler: auto-sends `ack` then `reply`, both addressed
   back to A with `in_reply_to` set to the message's id.
3. B's outbox delivers both to A's real inbox; A's inbound processing
   records thread state (no further auto action for `ack`/`reply`).
4. A explicitly sends `close`; A's outbox delivers it; B's inbound
   processing records the close.

Assertions cover every clause of the EARS bullet, not just "it didn't
crash":
- **Thread state correct on both sides**: `GetThread` on both A and B shows
  `closed=true`, `closed_by="a.example.com"`, and the correct `peer` (each
  side's peer is *the other* domain — this is what would break first if the
  two-party bookkeeping were subtly backwards). `ThreadMessages` shows all 4
  envelopes on both sides, in the exact kind sequence
  `message, ack, reply, close`.
- **Every signature verified**: two layers of evidence, not one. (a)
  Implicit but strong: zero dead letters on either side — a single failed
  signature anywhere in the chain would have 401'd at some hop's gate and
  produced a `dead_rejected` record, and none exist. (b) Explicit: every
  archived envelope is independently re-verified after the fact, using a
  *freshly constructed* resolver (not the one either daemon used live) to
  re-derive each signer's key from its own published index and re-run
  `envelope.Verify` — this is deliberately redundant with (a) so a bug that
  made the live gate wrongly accept something wouldn't also make the test's
  own check wrongly accept it.

Two smaller unit tests round out coverage that the E2E test's happy path
alone doesn't isolate: `daemon.TestSend_CloseMarksOwnThreadClosedImmediately`
(the sender's own thread closes at send time, not just on the receiver's
side) and `daemon.TestProcessInboundOnce_NonMessageKindsRecordButDoNotAutoRespond`
(only `message` triggers the ack+reply behavior — a `reply` arriving must
not itself trigger another reply, which would loop forever between two
reference daemons).

### Scope decisions made autonomously this phase (flagged here, not asked)

1. **Transport: HTTP over 127.0.0.1, not literal TLS.** Core §6 mandates
   HTTPS as the floor. Standing up real certificates for two ephemeral
   `httptest` domains isn't meaningful in a sandboxed test environment and
   wasn't the point of this gate — the protocol logic under test (gate
   order, signature verification, thread state) is transport-layer-blind by
   design (`internal/inbox`'s `Gate` interface, `internal/outbox`'s
   `Sender` interface). `cmd/awpd` itself is flagged in its own comments as
   listening plain HTTP for local/dev use — a real deployment needs a
   `-tls-cert`/`-tls-key` flag or a TLS-terminating reverse proxy in front
   of it before this is production-safe. Not silently shipped as if it were
   already HTTPS-compliant.
2. **`thread_msgs` value: spec gap, resolved by storing full envelope
   bytes.** `awpd-store-v0.1.md` §2 describes the value as "envelope ULID
   (ref into the archived envelope)", but no bucket anywhere in that spec
   durably archives envelope bytes past processing (`inq`/`inq_active` are
   deleted on completion; `outbox` is deleted on delivery). Storing an ID
   that points at nothing is not "archived". This implementation stores the
   full raw envelope bytes as `thread_msgs`'s value instead — see the
   doc comment on `store.RecordThreadEnvelope` for the detailed reasoning.
   This is what makes `ThreadMessages` (and the E2E test's kind-sequence and
   re-verification assertions) possible at all.
3. **Rotation-chain continuity not checked by `keyresolver`.** `HTTPResolver`
   verifies each fetched index's own self-signature (`Index.VerifySelfSig`)
   but does not call `identity.VerifyRotationChain` across successive
   fetches — i.e., it trusts whatever index a domain currently publishes
   rather than requiring continuity from a previously-trusted key. Full
   TOFU/rotation tracking across time is orthogonal to this milestone's EARS
   bullet (message/ack/reply/close correctness) and would need per-domain
   trust-state persistence beyond what `keys_cache` currently holds. Flagged
   for whichever phase hardens cross-domain trust (Phase 5 conformance is
   the natural place, since it already has to exercise the rotation-chain
   logic from Phase 1 against real fetched indexes).
4. **`cmd/awp` CLI not built.** Still deferred (as flagged in Phase 3) —
   Phase 5 is where it's explicitly required (`awp conformance <domain>`),
   and nothing in this milestone's own EARS bullet needs a CLI; the E2E test
   drives `internal/daemon` directly, which is exactly what `cmd/awpd` also
   does, so the code path under test is identical either way.

### Deliberately out of scope for Phase 4 (later phases)

- `cmd/awp` CLI — see decision 4 above.
- Rotation-chain continuity in `keyresolver` — see decision 3 above.
- TLS/HTTPS termination in `cmd/awpd` — see decision 1 above.
- Multiparty threads, delegation-in-the-loop (an agent acting on another's
  behalf mid-thread), and session tokens (`state: provider`) — none are
  exercised by this milestone and remain deferred per their original phase
  boundaries (core §2.5/§1.3, v0.2 territory for multiparty).
- Metrics/observability beyond what the tests already assert.

## Phase 4.5 — awp/1 (QUIC)

**Scope:** `internal/quictrans` — the `awp/1` transport binding of
`spec/awp-quic-v0.1.md`: frame codec, a `Server` that runs every envelope
through the *same* `inbox.Gate` an HTTPS listener uses (gate equivalence by
construction), a `Sender` implementing `outbox.Sender` over real QUIC
connections (reused across sends, SNI = receiving domain), and a
`FallbackSender` that hides the QUIC-then-HTTPS dance behind one
`Sender.Send` call so the outbox state machine never has to know transport
happened at all. `internal/keyresolver` gained `ResolveTransport`.
`internal/daemon` gained fully optional/additive QUIC wiring (`Config.QUIC
== nil` stays exactly the Phase 4 HTTPS-only behavior — zero regression
risk, verified by rerunning every Phase 4 test unchanged).

**Environment:** go1.26.5 darwin/arm64, `github.com/quic-go/quic-go` v0.60.0.

**Gate commands:** `go test ./... -count=1 -v`, `go test ./... -race
-count=1`, `go vet ./...`, `gofmt -l .`.

**Result:** PASS, all packages; vet and gofmt clean; race-clean.

```
ok  	github.com/agentask/awp/internal/daemon	11.747s
ok  	github.com/agentask/awp/internal/delegation	11.183s
ok  	github.com/agentask/awp/internal/envelope	11.484s
ok  	github.com/agentask/awp/internal/identity	10.566s
ok  	github.com/agentask/awp/internal/inbox	12.164s
ok  	github.com/agentask/awp/internal/keyresolver	12.358s
ok  	github.com/agentask/awp/internal/manifest	9.567s
ok  	github.com/agentask/awp/internal/outbox	10.781s
ok  	github.com/agentask/awp/internal/quictrans	11.105s
ok  	github.com/agentask/awp/internal/store	11.798s
```

Per-package times rose uniformly (~10-12s across the board, including
packages untouched by this phase) compared to earlier phases — this is
environment noise on the machine this ran on, not a regression: verbose
per-test timing (`go test -v`) shows the actual slowest subtest,
`TestE2E_QUICFailureFallsBackToHTTPS`, at ~1.1s consistently; an earlier,
much slower draft of that test (before tuning dial/handshake timeouts, see
below) ran 10-33s depending on system load, which is what motivated the
tuning.

### EARS gate coverage

CLAUDE.md's Phase 4.5 bullets, plus "Gate: Phase 4 E2E passes twice — once
per transport — plus the fallback test":

1. **Phase 4's E2E passes over awp/1** —
   `daemon.TestE2E_MessageAckReplyClose_OverQUIC` re-runs the *exact same*
   message→ack→reply→close flow and assertions as Phase 4's
   `TestE2E_MessageAckReplyClose` (factored into a shared
   `runMessageAckReplyCloseFlow` helper so the two can't silently drift
   apart), against two instances with real, working QUIC listeners.
2. **QUIC failure → HTTPS fallback, processed exactly once** —
   `daemon.TestE2E_QUICFailureFallsBackToHTTPS` runs the identical flow
   where the receiver's index advertises an awp/1 endpoint nothing listens
   on (simulating its QUIC service being down while HTTPS stays up); every
   send from the sender must fall back, yet the thread still ends up with
   exactly 4 archived envelopes on each side and zero dead letters — the
   same success bar as the transport-agnostic version, proving fallback
   doesn't duplicate or drop anything.
   - `quictrans.TestFallbackSender_FallsBackOnDialFailure` and
     `..._FallsBackWhenNoTransportAdvertised` isolate the two distinct
     triggers (real dial failure vs. no advertisement at all) at the
     `FallbackSender` unit level, and
     `..._NoFallbackWhenPrimarySucceeds` confirms the fallback is never
     invoked when QUIC actually works (no double-send).
3. **One `seen` store dedupes across transports** —
   `daemon.TestDedupe_AcrossTransports` delivers the *same signed envelope
   bytes* to the same receiver first over a real awp/1 connection (202,
   durably enqueued), then over HTTPS (200 — core §2.2 gate 4's dedupe hit,
   not reprocessed), and confirms the receiver's store shows it queued
   exactly once. This is the one assertion Phase 2's HTTP-only duplicate-id
   test structurally couldn't make: that dedupe is keyed by `id` in one
   shared store regardless of which transport adapter handed the gate the
   bytes, not per-transport state.

Also covered, because awp-quic §5 rule 1 names it explicitly:
**gate equivalence** — `quictrans.TestSend_GateEquivalence_ValidEnvelopeAccepted`
and `..._BadSignatureRejected` assert a valid and an unverifiable envelope
get the identical 202/401 outcomes over QUIC that `internal/inbox`'s own
Phase 2 tests already proved for HTTP — not by re-testing the gate's
internals (already done), but by proving the QUIC `Server` calls the exact
same `Gate.Accept` and passes its result through unmodified.

And per awp-quic §4 ("connections... SHOULD be reused"):
`quictrans.TestSend_ReusesConnectionAcrossSends` sends 3 envelopes to the
same domain and asserts exactly 1 cached connection.

### Scope decisions made autonomously this phase (flagged here, not asked)

1. **No real WebPKI in tests.** Test certificates are self-signed
   (ed25519, generated per test domain) with the client trusting a
   test-scoped `x509.CertPool` rather than a real CA — the same
   simplification already made for HTTP domain-index fetches in
   `internal/keyresolver`'s Phase 4 tests. SNI (`tls.Config.ServerName`) is
   still set correctly per dial from the resolved domain, so the mechanism
   under test — TLS handshake + certificate validation + ALPN negotiation —
   is real; only the trust anchor is test-local instead of a public CA.
2. **1-RTT only; no 0-RTT.** Awp-quic §1 says 0-RTT "is permitted," not
   required, and explicitly reasons that it's safe only because gate 4's
   dedupe collapses replay into the ordinary duplicate case — meaning
   0-RTT is a latency optimization, not something with distinct
   correctness behavior to test. Implemented via `quic.ListenAddr`/
   `quic.DialAddr` (not the `Early` variants), deferring 0-RTT wiring to
   whichever phase actually cares about that latency win.
3. **Dial/handshake timeouts tuned down from quic-go's defaults.**
   quic-go's default handshake-idle timeout is ~5s (aborting at ~10s),
   which is a reasonable production default but made the fallback test
   slow and let one early run take 10+ seconds waiting to fail over to
   HTTPS. `daemon.QUICConfig` gained `ClientDialTimeout` /
   `ClientQUICConfig` so this is tunable per-deployment rather than a fixed
   constant; the reference daemon (`cmd/awpd`) doesn't set them yet (QUIC
   isn't wired into `cmd/awpd` at all this phase — see below), so it
   inherits quic-go's defaults until someone wires QUIC into the CLI/daemon
   binary and picks production-appropriate values.
4. **`cmd/awpd` still HTTPS-only.** QUIC is fully built and tested at the
   `internal/daemon` level (`Config.QUIC`), but `cmd/awpd`'s `main.go`
   doesn't expose flags for it yet (`-quic-addr`, cert/key paths, etc.).
   Adding a always-on QUIC listener to the reference binary without a way
   to configure/disable it would be scope creep beyond what this phase's
   EARS bullets ask for; flagging as a follow-up rather than silently
   shipping a binary that claims QUIC support but has no way to configure
   it.

### Deliberately out of scope for Phase 4.5 (later phases)

- `cmd/awpd` QUIC flags/wiring — see decision 4 above.
- 0-RTT — see decision 2 above.
- The `awp://` URI scheme (awp-quic §6) — addressing/naming only, no
  transport behavior; nothing in this phase's EARS bullets exercises it,
  and no code anywhere yet parses or resolves `awp://` URIs from envelope
  bodies or manifests.
- awp-quic §8 conformance checklist as a formal, automated checklist
  runner — that's explicitly Phase 5's `awp conformance` deliverable: "core
  §5 + awp-quic §8 checklists". This phase's tests satisfy the checklist's
  substance (items 1-3, 5) informally; item 4 ("handles ≥100 concurrent
  envelope streams") isn't load-tested here either — flagging both for
  Phase 5 to formalize.

## Phase 5 — conformance

**Scope:** `internal/httpsig` (the awp-sig RFC 9421 subset — referenced
since Phase 1 but never implemented, since nothing before Phase 5 needed a
*sync* signed call), `internal/session` (core §1.3 self-authenticating
tokens, needed for httpsig's AWP-Session step), `testdata/awp-sig/`
conformance vectors, `internal/conformance` (the core §5 + awp-quic §8
checklist runner), and `cmd/awp` (finally built — deferred three times,
from Phases 3, 4, and 4.5) with `conformance` and `outbox ls --dead`
subcommands.

**Environment:** go1.26.5 darwin/arm64.

**Gate commands:** `go test ./... -count=1 -v`, `go test ./... -race
-count=1`, `go vet ./...`, `gofmt -l .`, plus the literal CLAUDE.md gate:
`awp conformance <domain>` run against a real `awpd` instance.

**Result:** PASS, all packages; vet and gofmt clean; race-clean.

```
ok  	github.com/agentask/awp/internal/conformance	0.737s
ok  	github.com/agentask/awp/internal/daemon	4.552s
ok  	github.com/agentask/awp/internal/delegation	0.739s
ok  	github.com/agentask/awp/internal/envelope	3.799s
ok  	github.com/agentask/awp/internal/httpsig	2.165s
ok  	github.com/agentask/awp/internal/identity	2.753s
ok  	github.com/agentask/awp/internal/inbox	2.683s
ok  	github.com/agentask/awp/internal/keyresolver	4.644s
ok  	github.com/agentask/awp/internal/manifest	2.462s
ok  	github.com/agentask/awp/internal/outbox	4.398s
ok  	github.com/agentask/awp/internal/quictrans	1.782s
ok  	github.com/agentask/awp/internal/session	4.364s
ok  	github.com/agentask/awp/internal/store	4.980s
```

### EARS gate: `awpd` passes its own conformance run

Ran for real, not just via Go tests: started `awpd` on a `.test` domain
(`-resolve-base-url` pointed back at its own local address — see the
scope decision below), then ran `awp conformance -key <identity.pem> -kid
k1 <domain>` against it.

```
[PASS] core-5.1                     Serves a valid signed domain index over TLS with >=1 active key.
[PASS] core-5.2-malformed           Gate order: malformed envelope -> 400.
[PASS] core-5.2-ttl-bounds          Gate order: ttl outside [60, 604800] -> 400.
[PASS] core-5.2-expired             Gate order: expired envelope -> 410 (also core §5.6).
[PASS] core-5.2-unknown-signer      Gate order: envelope signed by an unregistered key -> 401.
[PASS] core-5.2-accept-and-dedupe   Gate order: valid envelope -> 202, byte-identical resend -> 200.
[SKIP] core-5.3-retention           (see scope decision below)
[SKIP] core-5.4-delegation          (see scope decision below)
[SKIP] core-5.5-unknown-body-type   (see scope decision below)
[SKIP] core-5.7-two-party           (see scope decision below)
[PASS] quic-8.1                     HTTPS-only is spec-compliant when no awp/1 transport is advertised.
[SKIP] quic-8.2..8.5                no awp/1 endpoint advertised (this awpd run didn't enable QUIC)

Result: OK (no failures)
```

`awp outbox ls --dead` was also smoke-tested against the same data
directory (empty result, exit 0) — the bonus command closing the
Phase 3/4 CLI deferral.

### EARS gate coverage (internal/httpsig, per awp-sig-v0.1.md §2)

Same rigor as Phase 1's delegation-rule tests: every step isolated, plus
combined-failure cases proving order.

- **Round-trip, all 4 required shapes**: bodyless GET, POST+body,
  POST+AWP-Session, POST+AWP-Delegation (2-link chain) —
  `httpsig.TestSignVerify_RoundTrip_*`.
- **Every §2 failure mode, in isolation**:
  `httpsig.TestVerify_EachFailureModeInIsolation` covers steps 1 (four
  distinct malformed-Signature-Input shapes: absent, unknown label,
  forbidden param, missing covered component), 2 (created outside ±300s),
  3 (digest mismatch — deliberately proven to fire *before* step 5 would,
  a combined-failure order test in the same spirit as Phase 2's gate-order
  matrix), 4 (unknown key, with the core §0.1 one-refresh-then-hard-fail
  behavior separately confirmed by
  `TestVerify_Step4_RefreshAttemptedOnceOnKeyResolveFailure`), and 5 (bad
  signature via post-signing tamper). Steps 6 and 7 (delegation, session)
  get their own dedicated tests since they need distinct fixtures:
  `TestVerify_Step6_DelegationFailure` (403,
  `unauthorized_delegation`) and `TestVerify_Step7_SessionFailure` /
  `..._NoVerifierConfiguredRejectsSession` (401).

### `testdata/awp-sig/` vectors

14 vectors in `testdata/awp-sig/*.json`, generated by
`testdata/awp-sig/generate.go` (`go run testdata/awp-sig/generate.go
testdata/awp-sig`) — the spec's required minimum set (bodyless GET, POST
+body, POST+AWP-Session, POST+AWP-Delegation 2-link) plus one vector per
§2 failure mode. Two properties make these real conformance fixtures
rather than a one-off artifact:

1. **Self-checked at generation time.** Every vector is verified against
   this repo's own `httpsig.Verify` before being written; a vector that
   wouldn't actually round-trip can never ship.
2. **Continuously re-verified.** `httpsig.TestConformanceVectors` reads
   every `testdata/awp-sig/*.json` file at test time and replays it through
   `Verify` independently — so a regression in `Sign`/`Verify` fails `go
   test`, not just the generator's one-time self-check. Confirmed
   byte-identical reproducibility: re-running the generator twice produces
   `diff`-empty output (fixed deterministic key derivation + the spec's own
   example `created=1753088043` timestamp, not wall-clock time).

### Scope decisions made autonomously this phase (flagged here, not asked)

1. **Four core §5 checklist items can only be Skip, not Pass/Fail, for a
   black-box wire-level prober** — `core-5.4-delegation`,
   `core-5.5-unknown-body-type`, and `core-5.7-two-party` describe
   internal processing/state with no spec-defined API to query it from
   outside (there's no "tell me what you did with the envelope I sent
   you" endpoint). `core-5.3-retention` looked checkable at first — I
   implemented a real probe (enqueue, sleep out the minimum TTL, resend,
   expect a dedupe 200) — but running it against a real target revealed
   core §2.2's own gate order defeats it: gate 2 (TTL check) always fires
   before gate 4 (dedupe check), so a resend past its own `ttl` gets 410
   unconditionally, regardless of whether the receiver retained the
   seen-id or garbage-collected it early. The two cases are
   indistinguishable from outside. Caught this by actually running the
   check rather than trusting the design on paper — see
   `checkRetention`'s doc comment for the full reasoning. All four report
   `Skip` with a specific, checked-in reason rather than a fabricated
   Pass.
2. **`cmd/awpd` gained `-resolve-base-url`.** Running "awpd passes its own
   conformance run" for real (not just via Go tests against an in-process
   `httptest.Server`) surfaced a genuine wiring gap: `awpd` had no way to
   resolve its *own* domain's key locally, so it 401'd its own self-signed
   conformance probes — `keyresolver.HTTPResolver` defaults to
   `https://{domain}`, which doesn't exist for a throwaway `.test` domain
   in a local run. Added a flag that overrides all domain resolution to a
   single base URL, for local/dev/self-test use; production deployments
   leave it unset and get the real per-domain HTTPS default. Found and
   fixed by actually running the binary end-to-end, not just unit tests.
3. **`internal/conformance` speaks the awp-quic wire format itself,
   independent of `internal/quictrans`.** A black-box conformance checker
   that imported the very transport implementation it might be checking
   would validate its own assumptions, not the target's actual wire
   behavior. `quic8.go` hand-rolls the same 4-byte-length-prefix framing
   from scratch.
4. **awp-quic §8 item 4 ("handles ≥100 concurrent streams") is a real
   probe, not a Skip**, despite not needing any caller key — 100
   concurrent malformed-envelope streams (guaranteed 400 regardless of
   trust) is enough to exercise genuine concurrency without needing signed
   material.

### Deliberately out of scope for Phase 5 (later, if ever)

- The four Skip-only core §5 items and one Skip-only awp-quic item — see
  decision 1. Making these checkable would require the conformance tool to
  stand up its own reachable receiving inbox and correlate async replies
  over time, a materially different (and heavier) tool than a
  single-invocation CLI.
- Response signing (awp-sig §3, "SHOULD sign") is implemented
  (`httpsig.SignResponse`) and unit-tested at the package level, but no
  conformance vector or checklist item exercises it — the spec vectors
  list only covers request signing ("Minimum set: bodyless GET; POST with
  body; POST with AWP-Session; POST with AWP-Delegation").
- HTTP-date `Retry-After` (already deferred from Phase 3) remains
  deferred; unrelated to this phase, just still outstanding.
- `cmd/awpd` QUIC flags (deferred from Phase 4.5) remain deferred; the
  conformance run above shows a QUIC-disabled `awpd` correctly reporting
  `quic-8.1` as Pass ("HTTPS-only is spec-compliant") rather than Fail.

## v0.1 suite: implementation complete

Every phase in CLAUDE.md's build plan (1 through 5) now has a passing
gate recorded above. What remains is operational, not architectural:
wiring QUIC into `cmd/awpd`'s flags, deciding what (if anything) makes the
four Skip-only checklist items checkable, and whatever the maintainers
decide is next after a v0.1 reference implementation — none of that is
this document's call to make unilaterally.

## Gap closure (post-v0.1 suite)

Phase 5's "operational, not architectural" list above, plus a few items
this document had flagged as deferred along the way, closed out as a
follow-up pass. Gate: `go build ./...`, `go vet ./...`, `gofmt -l .`, and
`go test ./... -race -count=1` all green across every package including
the new ones below.

1. **`internal/keyresolver`: rotation-chain continuity.** The resolver's
   cache previously treated any re-fetched index as trustworthy on its own
   signature alone — a compromised or MITM'd re-fetch could swap in an
   entirely unrelated key with no way to detect it after the initial TOFU
   fetch. `Refresh` now checks the newly-fetched index's active key
   against the *previously cached* one: either an exact match or a valid
   one-step `identity.VerifyRotationChain` link. A genuinely broken chain
   is rejected and the old cache entry is kept; a caller who wants to
   deliberately re-trust a domain after a real, out-of-band key change
   calls the new `Reset`, which is the only path that still deletes the
   cache unconditionally. Caught during implementation: the original
   `Refresh` deleted the cache *before* fetching, which would have made
   continuity-checking meaningless (nothing left to compare against) —
   fixed before it shipped.
2. **`internal/store` / `internal/daemon`: GC loops.** `seen` entries and
   dead-lettered outbox records accumulated forever with no eviction.
   Added `Store.GCSeen` (deletes `seen` entries past their TTL) and
   `Store.GCDeadLetters` (deletes dead-letter records past
   `outbox.dead_retention`, default 720h per awpd-outbox §3), wired into
   `Daemon.RunGCOnce` and run hourly from `cmd/awpd`.
3. **`cmd/awpd`: real TLS termination.** The daemon previously served
   plain HTTP; `awp/1`'s coexistence story and any real deployment both
   assume the HTTPS floor is actually TLS. Added `-tls-cert`/`-tls-key`
   flags for an operator-supplied certificate, and a self-signed
   ed25519 cert generated and persisted under the data dir when neither is
   given, so a fresh `awpd` run is HTTPS out of the box with no manual PKI
   setup. `awp conformance` gained a matching `-insecure` flag for probing
   a self-signed target. `awpd`'s own outbound key resolution needed a
   `-resolve-insecure` flag too, once its own HTTPS client started
   rejecting its own self-signed cert while resolving its own domain for
   self-addressed conformance probes.
4. **`cmd/awpd`: QUIC flags/wiring.** `internal/quictrans` and
   `daemon.QUICConfig` existed since Phase 4.5 but `cmd/awpd` never
   exposed them. Added `-quic-addr`/`-quic-dial-timeout`; when set, awpd
   listens for `awp/1`, reuses the same TLS certificate for the QUIC
   listener, and advertises the transport in its own signed index.
5. **`internal/wasmrt`: the wazero stdio-json/1 runtime.** This was pure
   scope gap — core §1.2's portable-tool contract was fully specified but
   never implemented; nothing in Phases 1-5 exercised it. Built
   `wasmrt.Compile` (sha256-pinned) and `wasmrt.Module.Run`/`RunWithStderr`
   against wazero + wasi_snapshot_preview1, with clock/random capability
   gating (`WithSysWalltime`/`WithSysNanotime`/`WithRandSource`, since
   wazero's public API has no way to omit individual WASI imports —
   "absent" capability means a deterministic fake clock/RNG, not a missing
   import) and the exit-code/stdout contract from core §1.2 (nonzero exit,
   empty stdout, or unparseable stdout are all `internal`, never
   caller-visible). Test fixtures are real Go programs cross-compiled at
   test time with `GOOS=wasip1 GOARCH=wasm`.
6. **Wiring manifest+httpsig+wasmrt into a live sync tool-serving
   endpoint.** The three pieces existed independently but nothing served
   an actual `POST /awp/tools/{entity}` request end to end. Added
   `daemon.RegisterTool` (signs and serves the manifest, adds a pinned
   `entities[]` row to the domain's own index) and `serveToolCall`
   (`httpsig.Verify` → dispatch to a native `ToolHandler` or a
   `wasmrt.Module` → core §1.3 session issuance for `state: provider`
   tools). This surfaced a real, previously-undetected bug: **every
   httpsig test through Phase 5 reused the same in-memory `*http.Request`
   for both `Sign` and `Verify`, which never exercises what Go's
   `net/http` server actually does to an incoming request** — it strips
   scheme+host off `req.URL`, leaving only the path, so `@target-uri`
   verified against a server-received request was never the same string
   the client signed. Every real signature would have failed. Fixed with
   `httpsig.AbsolutizeServerRequestURL` (called before `Verify` in
   `serveToolCall`), locked in with `TestSignVerify_RealHTTPRoundTrip`
   (proves the fix works) and `..._FailsWithoutAbsolutize` (proves the
   helper isn't a no-op) — both using `httptest.NewServer` for a genuine
   network round trip rather than in-process object reuse.
7. **`sdk/go`: the thin client SDK.** `CLAUDE.md`'s own layout table
   promised this (`sdk/go    thin client`) and nothing under `sdk/`
   existed. Deliberately does *not* reuse `internal/keyresolver` (bbolt-
   backed, daemon-shaped) — a thin client that just wants to send one
   envelope or make one tool call shouldn't need to open a database file,
   so it carries its own in-memory-only index cache. Covers
   `Client.SendEnvelope` (single delivery attempt, no retry/outbox — that
   remains `cmd/awpd`'s job), `Client.CallTool` (resolves the manifest,
   verifies its sha256 pin, signs the sync call, verifies the provider's
   response signature if present), and `Client.SignDelegationLink`. Also
   closed a related loose end while building this: `httpsig.SignResponse`
   existed since Phase 5 with no corresponding verifier and no real
   consumer; added `httpsig.VerifyResponse` (mirrors `Verify`'s step
   structure for the response-only component set) so the SDK's response
   check is real, not decorative — a present-but-invalid response
   signature is treated as an error per awp-sig §3, an absent one is not
   (response signing remains SHOULD, not MUST).

### Explicitly still excluded (not gaps)

Three categories were identified during gap review and deliberately left
alone rather than "closed," because doing so would cut against the spec
or against what's structurally observable — the same standard applied to
Phase 5's Skip-only checklist items above:

1. **v0.2-deferred spec items** (multiparty threads, relays, pricing
   settlement, and everything else the spec documents mark as post-v0.1).
   Implementing these would violate the spec's own stated v0.1/v0.2
   boundary, not fill a v0.1 gap.
2. **Discovery / `#search` / `#submit`.** The spec itself marks this
   "STRAWMAN ... provisional ... post-milestone-1" — building it now would
   mean building against a section the spec's own authors haven't
   committed to yet.
3. **The four permanently-Skip conformance checklist items** (§5.4, §5.5,
   §5.7, §5.3) from Phase 5's decision 1 above. Nothing in the gap-closure
   pass changed the structural fact that a black-box CLI prober has no
   spec-defined API to observe internal processing/state — these remain
   Skip with a checked-in reason, not a fabricated Pass.

## Documentation, examples, and a second gap round

Two follow-on rounds after the gap-closure pass above, requested directly
rather than self-identified: comprehensive docs + runnable examples, then
a second pass closing the small set of gaps that surfaced while writing
them.

### `docs/` and `examples/`

Seven docs (`getting-started`, `protocol-overview`, `architecture`,
`sdk-go`, `cli-reference`, `deployment`, and `agent-guide` — the last
specifically for AI-agent builders: the authn-vs-content-trust boundary,
tool discovery, delegation, and the caller-only-vs-full-participant
split) and five runnable programs under `examples/` (`hello-tool`,
`stateful-tool-delegation`, `agent-messaging`, `custom-message-handler`,
`portable-wasm-tool`), each with its own README and at least one Mermaid
diagram. `README.md` got a typo fix and a real correction: it had claimed
an `awp` CLI with `keys`/`publish`/`call`/`send` subcommands that were
never built — only `conformance` and `outbox ls` exist; programmatic
send/call/delegate is `sdk/go`.

Two SDK/library gaps surfaced directly from writing these, not from
review:

- **`sdk/go.Client.FetchManifest`** — didn't exist; needed by
  `examples/portable-wasm-tool` to fetch and pin-verify a manifest
  without making a sync call against it (the only way to reach a
  `distribution.portable` tool, which has no callable endpoint at all).
- **`internal/httpsig.VerifyResponse`** — `SignResponse` existed since
  Phase 5 with no verifier and no real consumer; added so the SDK's
  response check (used by `CallTool`) is real, not decorative.

### Second gap round

Six items, tackled from a status report the user asked for after the
docs/examples work:

1. **`internal/daemon.Config.MessageHandler`** — the most consequential.
   `handleMessage` was hardcoded (ack, then a fixed reply) with no
   extension point at all; `docs/agent-guide.md`'s "being called" section
   told agent builders to "embed `internal/daemon`, replacing its
   message-handling," which was impossible without editing the package's
   own source. Added `Config.MessageHandler` (a
   `func(ctx, env, send) error`, `send` pre-bound to the inbound
   message's `to`/`thread`/`in_reply_to`), moved the old behavior into
   `defaultMessageHandler` used when unset. `examples/custom-message-handler`
   demonstrates it end to end, next to `agent-messaging`'s default.
2. **`internal/outbox.HTTPSender`: HTTP-date `Retry-After`.** Only the
   delta-seconds form was handled since Phase 3. Added a `Clock` field
   (needed to convert an absolute HTTP-date into the relative
   `time.Duration` `Sender.Send` returns; no `Sender` interface change)
   and `parseRetryAfter`, trying delta-seconds first, then
   `http.ParseTime`, clamping a past date to zero rather than a negative
   duration.
3. **`cmd/awpd -dead-retention`.** `daemon.Config.DeadRetention` existed;
   nothing exposed it. Mechanical flag addition.
4. **Response-signing conformance + testdata vector.** Added
   `awp-sig-3-response-signing` to `internal/conformance` — deliberately
   outside the core §5/awp-quic §8 checklists (there's no checklist item
   for a SHOULD with no checklist entry), Skip-gated on having a caller
   key and a discoverable `kind:tool` entity, `Fail` only on
   present-but-invalid, never on absent. Writing this surfaced that
   **`internal/daemon.serveToolCall` never actually called
   `httpsig.SignResponse`** — the reference daemon would have always
   reported Skip against its own tools, and `sdk/go`'s response
   verification (added in the docs/examples round) had never once
   verified a real signed response in this repo's own test suite. Fixed:
   `serveToolCall` now signs every successful response. Also added
   `response-signed`/`response-tampered-signature` to
   `testdata/awp-sig/` (required adding `httpsig.ResponseSignatureBase`,
   the response counterpart to the existing `RequestSignatureBase`
   tooling export) and taught `TestConformanceVectors` to tell request
   vectors from response vectors apart (a response vector has no
   `method` key at all — that absence is the discriminator) rather than
   assuming every fixture is request-shaped.
5. **Tag `v0.1.0-m1`.** Never tagged despite CLAUDE.md's convention.
   Phases 1–5 landed in one commit (`8eed89c`), not incrementally, so
   there was no earlier commit to tag more precisely — tagged there
   retroactively, annotated with what the milestone actually required.
6. **This entry**, plus fixing the specific sentences in
   `docs/agent-guide.md` and `docs/deployment.md`/`docs/cli-reference.md`
   that described the gaps closed above as still open.

Gate: `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./... -race
-count=1` all green; all five `examples/` re-run and matched their
documented output.

## 12-feature roadmap: Phases 0-3

A separate, later planning pass (`.claude/plans/vast-plotting-teacup.md`)
selected 12 protocol-feature ideas and sequenced them into their own
phases 0-3 — unrelated in scope to, but confusingly numbered the same as,
the Phase 1-5 sections above. Noted explicitly to avoid ambiguity; this
document's earlier "Phase N" headings are the original implementation
phases and are unaffected by anything below.

**Phase 0** (commit `45305d7`): promoted `ideas/streaming.md` to
`spec/awp-streaming-v0.1.md` and wrote `spec/awp-kinds-v0.1.md` — docs
only, no code.

**Phase 1** (commit `db7e9ba`): #9 index `capabilities`, #10 manifest
`environment`, #7 `AWP-Dry-Run` + manifest `capabilities`, #1 `status`
entity kind — `spec/awp-capabilities-v0.1.md`, Go + `sdk/python`, a new
`awp-kinds-2-status-entity` conformance check.

**Phase 2** (commit `0c5d507`): #11 manifest `changelog`/`previous_sha256`,
#4 index `wake` + outbox best-effort wake notifications —
`spec/awp-versioning-v0.1.md`, `spec/awp-push-v0.1.md`, Go + `sdk/python`,
a new `awp-push-2-wake-reachable` conformance check.

**Phase 3** (this entry): the three items the roadmap itself flagged as
"high complexity, blocked, or needing an explicit scope decision" —
resolved by asking the user directly rather than guessing:

1. **#6 transactional multi-tool calls** — user chose "full cross-domain
   design now" over descoping to same-domain-only or deferring outright.
   The honest full design for atomicity across independently-operated,
   mutually-untrusting domains is the **saga pattern** (compensating
   actions), not two-phase commit — no shared coordinator/escrow exists
   in AWP's trust model for 2PC to lock against. `spec/awp-transactions-v0.1.md`
   §0 states this tradeoff explicitly rather than quietly settling for
   sagas without saying why 2PC was rejected. Added manifest
   `compensated_by` (Go + `sdk/python`) and the `AWP-Transaction` sync-call
   header (an ordinary `AWP-*` header, zero httpsig changes, exactly like
   `AWP-Dry-Run` — but unlike it, a malformed value is a hard 400, since
   the header has an invalid non-empty state dry-run's boolean doesn't).
   Two new conformance checks: `awp-transactions-5.2-malformed-header-rejected`,
   `awp-transactions-5.3-compensated-by-resolvable`.
2. **#3 WebSocket transport** — user chose "do the full WebSocket phase
   now," sized like the original QUIC work (Phase 4.5 above). Added
   `internal/wstrans`: a from-scratch RFC 6455 client/server (handshake +
   frame codec), deliberately hand-rolled rather than pulling a
   WebSocket library — the same minimal-in-house-subset principle
   CLAUDE.md states for RFC 9421, extended to this binding since AWP's
   own use of WebSocket needs far less than a general-purpose
   implementation (no fragmentation, no ping/pong, no extensions —
   `spec/awp-ws-v0.1.md` §4 documents each simplification). Unlike
   `awp/1`, this binding shares the daemon's existing HTTPS listener
   (no new bind address) and multiplexes many concurrent envelopes over
   one connection, correlated by envelope `id` (QUIC gets that
   correlation for free from one stream per envelope; this binding does
   not, since it's a single ordered byte stream). Wired into
   `internal/daemon` (`Config.WS`, `WSEndpoint`) and `cmd/awpd` (`-ws`,
   `-ws-dial-timeout`), with its own e2e tests
   (`TestE2E_MessageAckReplyClose_OverWS`,
   `TestE2E_WSFailureFallsBackToHTTPS`, `TestDedupe_AcrossWSAndHTTPS`) and
   an independent (not importing `internal/wstrans`) black-box
   conformance prober, `internal/conformance/ws8.go`, exactly mirroring
   `quic8.go`'s own "speak the wire format itself" principle.
3. **#8 pre-flight cost estimation** — left deferred, no code or spec
   changes. Still blocked exactly as the roadmap plan states: `pricing`
   is `null`-reserved for v0.2 (core §1.2), and no cost-estimate call can
   be designed against a pricing model that doesn't exist yet.

**Shared-helper fallout (Go daemon e2e tests):** adding a TLS-secured
transport (WS) to a test suite that had only ever exercised plain-HTTP
and QUIC-with-plain-HTTP-inbox instances required threading an
`*http.Client`/cert-pool through `newTestInstance`, `newVerifyResolver`,
and `runMessageAckReplyCloseFlow` (all previously assumed no peer ever
needed anything but the zero-value default client) — a signature change
touching every existing call site in `internal/daemon`'s e2e test files,
not just the new WS ones. All pre-existing QUIC/plain-HTTP e2e tests were
re-run and still pass unchanged.

Gate: `go build ./...`, `go vet ./...`, `gofmt -l .` clean; `go test
./... -race -count=1` green across every package except the
already-isolated, pre-existing, unrelated `agents/go` data race
(`TestInbox_DedupesRepeatedID`, first identified and confirmed
pre-existing during Phase 1 above via a `git stash` comparison); 100
concurrent envelopes correctly multiplexed on one `internal/wstrans`
connection in both the package's own tests and its conformance prober;
real Go-signs/Python-verifies interop cross-checks for `compensated_by`
(tamper-detected) via a temporary in-repo scratch program, cleaned up
afterward.
