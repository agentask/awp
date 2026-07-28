# awp (Python)

The AWP reference Python SDK: a thin client for sending envelopes and
calling sync tools, plus the identity/envelope/manifest/delegation/httpsig
primitives it's built from. A full-parity Python port of `sdk/go`'s
`Client`.

"Thin" is deliberate: unlike a full daemon, this client keeps no on-disk
state, runs no retry/outbox state machine, and does not receive envelopes
on its own — it is for third-party Python programs that want to speak AWP
directly (sign, send, verify) without running one. Domain indexes are
cached in memory for the lifetime of the `Client` only.

This package is standalone: it does not import from or depend on
`agents/python/pyawp`. It reuses the same proven techniques (JCS library,
base64url helpers, ULID generation, timestamp formatting) but is its own
self-contained module tree.

## What it does

- `Client.fetch_index` / `Client.resolve` — fetch, cache, and TOFU-verify a
  domain's signed index (core §1.1); resolve `(domain, kid)` to a public
  key, rejecting revoked keys.
- `Client.fetch_manifest` — resolve an entity's manifest via its domain's
  index, verify its sha256 pin *before* parsing, then verify its signature
  (core §1.2).
- `Client.send_envelope` — build, validate (TTL, size), sign, and deliver
  one envelope to `to`'s resolved inbox. One delivery attempt: no retry, no
  persistence.
- `Client.send_stream_chunk` — the same, with `awp-streaming-v0.1.md` §2's
  `stream_chunk` body shape built for you. Producer-side only: this SDK's
  statelessness means it has no reassembly story, on purpose — a receiving
  daemon (`internal/daemon`'s `Config.StreamChunkHandler`) does that.
- `Client.call_tool` — resolve a tool's hosted endpoint, sign the sync call
  per the `awp-sig-v0.1.md` RFC 9421 subset, attach `AWP-Session`/
  `AWP-Delegation` headers when supplied, verify the response signature if
  present, and return `(output, session)` or raise on the `{code, detail,
  retryable}` error grammar.
- `Client.sign_delegation_link` — build and sign one core §2.5 delegation
  link.
- `Client.verify_inbound_envelope` — verify an *inbound* envelope's
  signature, resolving the sender's key via the same index/resolve
  machinery. sdk/go's equivalent lives in `internal/envelope` +
  `internal/identity`, directly importable by Go code in the same module;
  this SDK has no such `internal/` to reach into, so this method exists so
  a receiving node built on top of it doesn't have to hand-roll the same
  crypto.
- `awp.bootstrap` — generate an ed25519 keypair, build+self-sign a domain
  `Index`, and build+sign an entity `Manifest`, enough for a demo program
  to mint its own `*.local` identity and serve `/.well-known/awp.json`.
- `awp.delegation.verify` — full core §2.5 delegation-chain verification
  (all 7 rules), for a receiving node that needs to validate an inbound
  `AWP-Delegation` chain. `sdk/go`'s `Client` only *signs* one link; chain
  *verification* is receiver-side logic, ported here for full parity.
- `awp.httpsig` — the `awp-sig-v0.1.md` RFC 9421 subset: request signing,
  the 7-step server-side verification algorithm, and response-signature
  verification (absent = fine, present-and-invalid = always an error).

## What it doesn't do

- No persistence, no outbox, no retry/backoff/dead-lettering. Run a real
  daemon if you need that.
- No receiving loop of its own — `Client.verify_inbound_envelope` and
  `awp.bootstrap` give a receiving node the primitives it needs, but
  gating/dedup/enqueue (core §2.2) is the caller's responsibility.
- No rotation-continuity tracking across process restarts.
  `identity.verify_rotation_chain` verifies a chain you already have; a
  long-running verifier that needs persisted continuity checking across
  restarts needs more than this thin client provides.
- `identity.KeyValid`'s revocation-instant logic from the Go reference is
  a known spec gap (core §1.1 rule 3 requires comparing against "the
  revocation instant," but the wire schema has no `revoked_at` field) —
  not ported here since `sdk/go`'s own `Client` doesn't use it either;
  `Client.resolve` fails closed on any `revoked: true` key regardless of
  timing.

## Layout

```
awp/apperr.py       {code, detail, retryable} error grammar (core §2.6)
awp/b64url.py       unpadded base64url helpers (RFC 4648 §5)
awp/identity.py     Sig, canonicalization, sign/verify, Index/Key/Entity/Transport, rotation chain
awp/envelope.py     Envelope type, sign/verify, TTL/size validation, ULID ids
awp/manifest.py     Manifest type, sign/verify, sha256 pin check
awp/delegation.py   Scope/Link types, sign, full chain verification (core §2.5)
awp/httpsig.py      awp-sig-v0.1.md RFC 9421 subset: sign/verify request+response
awp/client.py       the thin Client
awp/bootstrap.py     identity/manifest bootstrap helpers for demo nodes
```

## Testing

```
uv sync
uv run pytest
```

Tests are fully offline: `tests/test_httpsig_vectors.py` loads every
vector from the repo's top-level `testdata/awp-sig/*.json` (self-checked
against the real Go implementation at generation time) and asserts both
sign- and verify-side behavior; other test files cover round-trip sign/
verify for every wire type and an in-process fetch/verify/call-tool
integration test using `httpx.MockTransport`.
