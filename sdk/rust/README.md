# awp (Rust)

The AWP reference Rust SDK: a thin client for sending envelopes and calling
sync tools, and the crypto primitives (JCS canonicalization, ed25519
signing, the awp-sig httpsig subset, core §2.5 delegation-chain
verification) that back it.

"Thin" is deliberate, mirroring `sdk/go`: unlike `awpd`, this crate keeps no
on-disk state, runs no retry/outbox state machine, and does not receive
envelopes on its own — it is for third-party Rust programs that want to
speak AWP directly (sign, send, verify) without running a daemon. Domain
indexes are cached in memory for the lifetime of a `Client` only.

## What's in scope

- `Client::fetch_index` / `resolve` — fetch, cache, and TOFU-verify a
  domain's signed index; resolve `(domain, kid)` to a public key, rejecting
  revoked keys.
- `Client::fetch_manifest` — resolve a principal's manifest via its
  domain's index, verify its sha256 pin (checked on raw bytes, before any
  parsing), then verify its signature.
- `Client::send_envelope` — build, validate (ttl bounds, 256 KiB size cap),
  sign, and POST an envelope to the recipient's resolved inbox. One
  synchronous delivery attempt, no retry.
- `Client::call_tool` — resolve a tool's hosted endpoint, sign the sync
  call per the awp-sig httpsig subset, set `AWP-Session`/`AWP-Delegation`
  headers when supplied, verify a response signature if present (absent is
  fine; present-and-invalid is always an error), and parse the
  `{output, session}` success shape or the `{code, detail, retryable}`
  error grammar.
- `Client::sign_delegation_link` — build and sign one core §2.5 delegation
  link.

Beyond literal parity with `sdk/go`'s `Client` — Go programs get this for
free by importing `internal/envelope`/`internal/identity` directly, since
`sdk/go` lives in the same module as those packages; a Rust program has no
such `internal/` to reach into, so this crate exposes the equivalent
surface directly:

- `Client::verify_inbound_envelope` — verify an *inbound* envelope's
  signature, resolving the sender's key via the same index/resolve
  machinery `resolve` uses.
- `identity::generate_keypair`, `Index`/`Key` construction +
  `Index::sign`, `Manifest` construction + `Manifest::sign` — enough for a
  demo program to mint its own `*.local` identity and serve
  `/.well-known/awp.json`.

## What's out of scope

No outbox, no persistence, no receiving loop, no daemon. A caller wanting
backoff/dead-lettering/resumable delivery across restarts should run
`awpd` instead of this SDK.

## Module layout

- `identity` — the core §0.1 JCS-then-ed25519 sign/verify primitive,
  domain `Index`/`Key`/`Entity`/`Transport` types, rotation-chain
  verification.
- `jcs` — hand-rolled RFC 8785 canonicalization over `serde_json::Value`.
  No mature, confirmed-trustworthy off-the-shelf Rust JCS crate existed
  when this was written; `tests/jcs_crosscheck.rs` validates this
  implementation's output against real `github.com/gowebpki/jcs`-produced
  bytes (the same library the Go reference daemon depends on).
- `envelope` — the async `Envelope` type, ttl/size validation, ULID
  generation.
- `manifest` — the `Manifest` type and sha256 pin verification.
- `delegation` — the `Link` type and full core §2.5 chain-verification
  rules (chain length, root-scope-bound, per-link signature/expiry,
  continuity, final-delegate, scope intersection).
- `httpsig` — the awp-sig-v0.1.md RFC 9421 subset: covered-component
  selection, signature-base construction, `Signature-Input`/`Signature`/
  `Content-Digest` header handling, request signing + 7-step verification,
  response signing + verification (with the "absent signature is fine,
  present-and-invalid is not" asymmetry preserved).
- `client` — `Client`, the thin SDK surface described above.
- `apperr` — the `{code, detail, retryable}` error grammar shared by sync
  and async paths.
- `b64` — the two base64 codecs the wire format uses: unpadded base64url
  for signatures/public keys, padded standard base64 for `Content-Digest`.
  Kept as distinct functions on purpose — conflating them is an easy bug.
- `rfc3339` — minimal hand-rolled RFC3339 parsing/formatting (millisecond
  precision for `Envelope.ts`/`Index.updated`/`Key.created`; no fractional
  seconds for delegation `Link.expires` — these are deliberately different
  formats, matching what the Go reference signs).

## Testing

`cargo test` runs:

- `tests/jcs_crosscheck.rs` — hand-rolled JCS output vs. real
  `gowebpki/jcs` bytes.
- `tests/vectors.rs` — every `testdata/awp-sig/*.json` conformance vector
  (bodyless GET, POST+body, POST+session, POST+2-link delegation, every
  numbered failure step, response signing, response tampering), plus
  sign-side byte-identical re-signing checks against the fixtures.
- `tests/roundtrip.rs` — sign/verify round trips and field-presence checks
  for every signed wire type, plus table-driven delegation-chain and
  rotation-chain rule tests.
- `tests/client_integration.rs` — `Client` end-to-end against a local mock
  HTTP server: index fetch+TOFU, manifest fetch+pin+signature, envelope
  delivery, and a signed sync tool call with response verification.

## Known spec gap

`identity::Key`'s `revoked` flag has no companion "revocation instant" in
the wire schema, yet core §1.1 rule 3 requires comparing a signed object's
timestamp against the revocation instant. This crate's `KeyValue`-equivalent
resolution (see `Client::resolve`, which simply fails closed on
`revoked: true`) does not attempt to reconstruct that instant — same gap,
same fail-closed resolution, as `sdk/go`.
