# CLAUDE.md — awpd build plan

Reference implementation of AWP (Agent Web Protocol). The seven documents in
`spec/` are the source of truth; when code and spec disagree, the spec wins
and the discrepancy gets flagged, not silently resolved.

## Fixed decisions — do not relitigate

- Module: `github.com/agentask/awp` · License: MIT · Monorepo.
- Go, single daemon binary `awpd` + CLI `awp`. No cgo anywhere.
- Deps: `gowebpki/jcs` (RFC 8785), `oklog/ulid/v2`,
  `tetratelabs/wazero`, `go.etcd.io/bbolt`, `quic-go/quic-go` (Phase 4.5).
  RFC 9421: minimal in-house subset per `spec/awp-sig-v0.1.md` — do NOT pull
  a 9421 library.
- HTTPS is the mandatory transport floor; `awp/1` QUIC is optional,
  envelope-only (`spec/awp-quic-v0.1.md`). Raw-TLS transport is rejected —
  see core §6 for why; do not reopen.

## Layout

```
cmd/awpd  cmd/awp
internal/identity    keygen, rotation chain, index build/verify
internal/manifest    types, sign, sha256 pinning
internal/envelope    types, JCS canon, sign/verify, ULID
internal/delegation  chain verification (core §2.5)
internal/inbox       HTTP handler + gate (core §2.2, strict order)
internal/outbox      state machine per spec/awpd-outbox-v0.1.md
internal/session     self-auth tokens per core §1.3 recommended format
internal/httpsig     awp-sig subset
internal/wasmrt      wazero stdio-json/1 (exact contract in core §1.2)
internal/quictrans   awp/1 binding (Phase 4.5)
internal/store       bbolt per spec/awpd-store-v0.1.md (tx boundaries!)
sdk/go               thin client
testdata/awp-sig     conformance vectors (Phase 5 output)
```

## Phases — one /goal each, gate must pass before the next starts

**Phase 1 — crypto core** (`internal/identity`, `internal/envelope`,
`internal/manifest`, `internal/delegation`)
- WHEN any signed object is round-tripped sign→verify, the system SHALL
  produce byte-identical JCS canon and verify.
- WHEN a rotation chain contains one broken link, verification SHALL reject.
- WHEN a delegation chain violates any core §2.5 rule (continuity, expiry,
  final-delegate, scope intersection, >8 links, empty root scope), it SHALL
  reject with the specific rule identified.
- Gate: `go test ./internal/...` green; table-driven tests per rule.

**Phase 2 — inbox + store**
- WHEN an envelope hits the gate, the system SHALL return the core §2.2
  status for each failure class, in gate order (test the ORDER, not just
  the codes).
- WHEN the process dies between gate 4 and gate 5, restart SHALL show
  either both `seen`+`inq` written or neither (kill-9 test).
- WHEN a duplicate `id` arrives on any transport, it SHALL be acked 200 and
  not reprocessed.
- Gate: gate-order matrix + crash-recovery test green.

**Phase 3 — outbox**
- WHEN the receiver is down, the system SHALL retry byte-identical envelopes
  with full-jitter backoff and dead-letter at TTL (pre-attempt check).
- WHEN a 429 carries Retry-After ≤ remaining TTL, it SHALL be honored.
- WHEN the daemon restarts mid-delivery, in-flight records SHALL return to
  queued with next_at=now.
- Gate: two local instances, induced failures; `awp outbox ls --dead`
  reflects truth.

**Phase 4 — milestone 1** (tag `v0.1.0-m1`)
- WHEN instance A sends `message` to instance B over HTTPS, the system SHALL
  complete message → ack → reply → close with every signature verified and
  thread state correct on both sides.
- Gate: the E2E test IS the release criterion.

**Phase 4.5 — awp/1**
- WHEN a QUIC attempt fails, the outbox SHALL deliver the same bytes over
  HTTPS and the receiver SHALL process exactly once.
- WHEN the same envelope arrives over both transports, one `seen` store
  SHALL dedupe it.
- Gate: Phase 4 E2E passes twice — once per transport — plus the fallback
  test.

**Phase 5 — conformance**
- Generate `testdata/awp-sig/` vectors (bodyless GET; POST+body;
  POST+AWP-Session; POST+AWP-Delegation 2-link; every awp-sig §2 failure).
- `awp conformance <domain>` runs the core §5 + awp-quic §8 checklists
  against any implementation.
- Gate: `awpd` passes its own conformance run.

## Conventions

- Errors: one grammar everywhere — `{code, detail, retryable}` (core §2.6);
  sync and async share the handler.
- All wall-clock reads behind an injected clock; tests never sleep real
  time.
- `internal/inbox` exposes a transport-blind `Gate` interface; HTTP and QUIC
  are thin adapters over it (awp-quic §5 equivalence depends on this).
- stderr from WASM modules → host logs only, never caller-visible.
- Git: phase-tagged milestones (`v0.1.0-m1` etc.); record each phase's
  passing gate output in `docs/experiments.md` before planning the next.
