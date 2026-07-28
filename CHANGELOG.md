# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project doesn't yet follow strict semantic versioning, since the
protocol itself is v0.1/draft (see each `spec/*.md`'s own "Status"
line) — expect breaking spec changes before a 1.0.

## [Unreleased]

Everything below predates this project's first public release — there
is no earlier published version to diff against, so this section
backfills the real development history rather than starting empty.
Future releases will replace this section with dated entries as usual.

### Added

- **Protocol core (v0.1)**: domain-anchored Ed25519 identity, JCS
  (RFC 8785) canonicalization, a signed domain index
  (`/.well-known/awp.json`) with key-rotation continuity, signed entity
  manifests with sha256 content pinning, signed async envelopes
  (`message`/`reply`/`ack`/`error`/`close`) with a fixed-order receiver
  gate, signed sync tool calls (`awp-sig`, a minimal RFC 9421 subset),
  and core §2.5 delegation chains (all 7 validity rules, table-driven
  tested). Reference daemon (`awpd`) + CLI (`awp`).
- **Outbox delivery**: full-jitter backoff retry, `Retry-After`
  honoring (both delta-seconds and HTTP-date forms), dead-lettering at
  TTL, crash recovery (in-flight records return to `queued` on
  restart, never silently lost or double-processed).
- **`awp/1` transport** (`internal/quictrans`): an optional QUIC
  binding for envelope delivery, with mandatory HTTPS fallback and
  cross-transport dedupe — proven with a real two-transport fallback
  test, not just asserted.
- **Portable tools**: sandboxed `wasm32-wasip1` / `stdio-json/1`
  execution via `wazero`, with host-enforced capability grants (clock,
  random — network/filesystem are not grantable in v0.1, by
  construction).
- **Conformance CLI**: `awp conformance <domain>` runs the core §5 and
  `awp-quic` §8 checklists (plus every extension below) against any
  AWP implementation reachable at a domain, not just this repo's own
  daemon — checklist items that are genuinely unobservable from
  outside a black-box prober report `Skip` with a documented reason,
  never a fabricated `Pass`.
- **Three SDKs**: `sdk/go` (a thin client reusing this module's own
  `internal/*` packages directly), and `sdk/python`/`sdk/rust`
  (independent from-scratch reimplementations of the same signing/
  canonicalization/verification logic, cross-checked against the Go
  implementation's actual byte-for-byte output — not just internally
  self-consistent).
- **Protocol extensions**, all purely additive on top of core — none
  change core's wire behavior, and every one is independently
  adoptable (see `docs/protocol-overview.md`'s "Extensions beyond core
  v0.1" section for the full writeup):
  - `awp-capabilities-v0.1.md` — index/manifest capability
    advertisement, a manifest sandbox-mode marker, and an
    `AWP-Dry-Run` sync-call header (an ordinary `AWP-*` header, no
    signing-algorithm change needed to cover it).
  - `awp-kinds-v0.1.md` — a `status` entity kind for health checks
    (with a conformance-checked response shape) and a `received`
    envelope kind (a passive receipt weaker than `ack`).
  - `awp-versioning-v0.1.md` — manifest `changelog` (an informational
    pointer) and `previous_sha256` (a self-asserted hash-chain link to
    the prior manifest version — with no archival guarantee that old
    manifest bytes remain fetchable anywhere).
  - `awp-push-v0.1.md` — an index `wake` field: a best-effort,
    unauthenticated delivery-retry hint fired only when a delivery
    attempt fails with a network error or 5xx.
  - `awp-transactions-v0.1.md` — saga-pattern multi-tool coordination
    (manifest `compensated_by`, an `AWP-Transaction` sync-call header)
    — deliberately the compensating-action pattern, not two-phase
    commit; see that document's §0 for why real cross-domain ACID
    atomicity isn't attempted between independently-operated,
    mutually-untrusting domains.
  - `awp-ws-v0.1.md` (`internal/wstrans`) — a second optional
    envelope-delivery transport that shares the daemon's existing
    HTTPS listener rather than needing a new port; a from-scratch RFC
    6455 client/server, hand-rolled rather than pulling a WebSocket
    library, multiplexing many concurrent envelopes on one connection.
  - `awp-streaming-v0.1.md` — chunked async responses (`stream_chunk`
    bodies: `stream_id`/`seq`/`final`/`data`), reassembled in order and
    tolerant of out-of-order delivery, bounded at 65,536 buffered
    chunks per stream with `error(refused)` on violation.
- Demo agents (`agents/go`, `agents/python`, `agents/rust`) forming a
  full triangle: every pair talks directly over real AWP (real Ed25519
  signatures, real JCS canonicalization, real signed HTTP), each backed
  by an LLM (xAI's Grok).
- Conformance test vectors (`testdata/awp-sig/`) covering bodyless GET,
  POST+body, POST+`AWP-Session`, POST+2-link `AWP-Delegation`, every
  numbered `awp-sig` failure step, and response signing/tampering —
  used by all three SDKs' own test suites, not just the Go daemon's.

### Fixed

- Two self-identified gap-closure rounds after the initial v0.1 build:
  a pluggable `Config.MessageHandler` (the daemon's message-handling
  was previously hardcoded with no extension point), HTTP-date
  `Retry-After` parsing (only delta-seconds was handled), response
  signing (`internal/daemon` was never actually signing its own
  sync-call responses despite the verifier already supporting it), and
  TLS/QUIC/wasm-runtime wiring gaps.
- A later roadmap audit found and closed: `internal/daemon` never
  actually advertised anything via `Index.Capabilities` despite having
  implemented the field; core §2.3's "unknown body types MUST produce
  `error(unsupported_body)`" rule had never been implemented anywhere
  (surfaced while implementing streaming, whose own conformance
  checklist depends on it); `sdk/rust` had never been brought current
  with any of the protocol extensions above, and `sdk/go`'s
  `CallOptions` was missing `AWP-Dry-Run`/`AWP-Transaction` support
  despite its data model already having the fields for free.
- A genuine, pre-existing data race in `agents/go`'s
  `TestInbox_DedupesRepeatedID`, isolated via a controlled `git stash`
  comparison and confirmed unrelated to any of the work above — see
  `docs/experiments.md` for the full diagnosis. Not yet fixed; CI
  excludes it from `-race` runs pending a dedicated fix (see
  `CONTRIBUTING.md`).

[Unreleased]: https://github.com/agentask/awp/commits/main
