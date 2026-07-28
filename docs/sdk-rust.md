# `sdk/rust` — the AWP Rust SDK

```toml
[dependencies]
awp = { path = "../sdk/rust" }
```

See `sdk/rust/README.md` for the module layout and `cargo test`
breakdown. Like `sdk/python`, this is a from-scratch Rust
reimplementation of the signing/envelope/manifest logic `internal/*`
implements in Go, not a wrapper around it — Rust can't import Go's
`internal/` packages either. Its own JCS canonicalization is cross-
checked against real `gowebpki/jcs`-produced bytes (`tests/jcs_crosscheck.rs`),
and its `awp-sig` implementation is checked against every
`testdata/awp-sig/*.json` conformance vector this repo generates from the
Go reference (`tests/vectors.rs`) — the same "don't just assert it,
cross-check it" bar `sdk/python` holds itself to.

## Thin, but self-contained the same way `sdk/python` is

Like both other SDKs, `Client` keeps **no on-disk state**, runs **no
retry/outbox state machine**, and **does not receive envelopes on its
own**. And like `sdk/python` (and unlike `sdk/go`), it carries
verification logic `sdk/go` gets for free by importing `internal/`
directly: `delegation::verify` (all 7 core §2.5 rules), the full
`httpsig` request/response verification algorithm, and
`Client::verify_inbound_envelope`. A Rust program building a receiving
node — not just a caller — has everything it needs here; there is no
separate "receiver-side" crate.

One difference from `sdk/python`: there is no dedicated bootstrap
module. Minting a demo identity is direct use of the public types —
`identity::generate_keypair()`, construct an `Index`/`Manifest` literal,
call `.sign(...)`. `tests/client_integration.rs`'s `build_peer` function
is exactly this pattern, inlined rather than factored into a helper.

## `Client`

```rust
pub struct Client {
    pub domain: String,
    pub kid: String,
    pub signing_key: SigningKey,
    pub http: reqwest::Client,
    pub index_url: Option<IndexUrlFn>, // Box<dyn Fn(&str) -> String + Send + Sync>
}

impl Client {
    pub fn new(domain: impl Into<String>, kid: impl Into<String>, signing_key: SigningKey) -> Self
}
```

All async methods take `&self` and are safe for concurrent use (the
index cache is a `Mutex<HashMap<...>>` internally). `index_url`
overrides where a domain's index is fetched from — local/test use,
exactly as `sdk/go`'s `IndexURL` and `sdk/python`'s `index_url` do;
`tests/client_integration.rs` points every fixture domain at a local
`hyper` mock server this way rather than real DNS.

## Reading: `fetch_index`, `resolve`, `fetch_manifest`

```rust
pub async fn fetch_index(&self, domain: &str) -> Result<Index, ClientError>
pub async fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, ClientError>
pub async fn fetch_manifest(&self, principal: &str) -> Result<Manifest, ClientError>
```

`fetch_index` fetches and verifies a domain's self-signature (TOFU: the
first fetch trusts whichever key the index names), caching the result
for the `Client`'s lifetime. `resolve` looks up a specific key within an
already-fetched-or-fetched-on-demand index, rejecting revoked keys.
`fetch_manifest` checks the `sha256` pin against the owning domain's
index (core §1.2 — before the signature, so a swapped manifest is caught
by the cheaper check first), then verifies the signature — the only way
to reach a `distribution.portable` tool, which has no callable endpoint
at all:

```rust
let m = client.fetch_manifest("wasm-tool.example#wordcount").await?;
// m.distribution.portable — download and run it yourself.
```

## Sending: `send_envelope`, `send_stream_chunk`

```rust
pub async fn send_envelope(&self, kind: &str, to: &str, thread: &str,
    in_reply_to: Option<String>, body: Value, ttl: i64) -> Result<Envelope, ClientError>
```

Builds, validates (ttl bounds, 256 KiB size cap), signs, and POSTs one
envelope to `to`'s resolved inbox — one synchronous delivery attempt, no
retry. `ttl` of `0` defaults to 3600s.

```rust
let thread = envelope::new_id();
client.send_envelope("message", "bob.example", &thread, None, json!({"type": "text", "text": "hi"}), 3600).await?;
```

```rust
pub async fn send_stream_chunk(&self, kind: &str, to: &str, thread: &str,
    in_reply_to: Option<String>, stream_id: &str, seq: i64, final_: bool,
    data: Value, ttl: i64) -> Result<Envelope, ClientError>
```

A thin wrapper over `send_envelope` with `awp-streaming-v0.1.md` §2's
body shape built for you (the parameter is `final_`, not `final` —
`final` is a reserved word in Rust). `stream_id` is a fresh
`envelope::new_id()` for `seq: 0` of a new stream, then the same value
for every later chunk; `seq` must strictly increase; `final_` is `true`
on exactly the last chunk. Producer-side only — no reassembly story,
same as `sdk/go`/`sdk/python`; a receiving daemon
(`internal/daemon`'s `Config.StreamChunkHandler`) does that buffering.

```rust
let stream_id = envelope::new_id();
client.send_stream_chunk("reply", "bob.example#agent", &thread, None, &stream_id, 0, false, json!({"text": "first chunk"}), 3600).await?;
client.send_stream_chunk("reply", "bob.example#agent", &thread, None, &stream_id, 1, true, json!({"text": "last chunk"}), 3600).await?;
```

## Calling: `call_tool`

```rust
#[derive(Default)]
pub struct CallOptions {
    pub session: Option<String>,
    pub delegation: Vec<Link>,
    pub dry_run: bool,
    pub transaction: Option<Transaction>,
}

pub async fn call_tool(&self, tool_principal: &str, input: Value,
    opts: CallOptions) -> Result<(Value, Option<SessionInfo>), ClientError>
```

Resolves `tool_principal`'s manifest, requires a `hosted` distribution
(portable-only tools aren't callable this way — use `fetch_manifest`
instead), signs the request per `awp-sig`, and sends it. If the provider
signs its response (awp-sig §3, `SHOULD`), the signature is verified
before the response is trusted — a present-but-invalid response
signature is an error; an absent one is not.

```rust
let (output, session) = client.call_tool("calc.example#multiply", json!({"a": 6, "b": 7}), CallOptions::default()).await?;
```

`session` is `Some` exactly when the tool is `state: provider` and this
call didn't already present a valid one — pass `session.token` back as
`CallOptions.session` on the next call to the same tool.

`dry_run` and `transaction` are both ordinary `AWP-*` headers — nothing
in `httpsig::sign`'s covered-component logic needed to change to add
either. Both are advisory: a provider that never declared support MAY
ignore either silently rather than reject the call.

```rust
pub struct Transaction {
    pub id: String,
    pub step: i64,
    pub coordinator: String,
}
impl Transaction {
    pub fn encode(&self) -> Result<String, ClientError> // base64url(JSON(self))
}
```

`Transaction` is the saga-coordination primitive from
`awp-transactions-v0.1.md` — see that document's §0 for why AWP models
multi-tool coordination as compensating actions rather than two-phase
commit. This crate only signs and sends the header; the coordinator-side
retry/compensate algorithm (the spec's §3) is the caller's own logic.

```rust
let opts = CallOptions { dry_run: true, ..Default::default() };
client.call_tool(tool, input, opts).await?;

let opts = CallOptions {
    transaction: Some(Transaction { id: txn_id, step: 0, coordinator: caller.domain.clone() }),
    ..Default::default()
};
client.call_tool(tool, input, opts).await?;
```

To call on someone else's behalf, attach a delegation chain — see
"Delegating" below.

## Verifying inbound envelopes: `verify_inbound_envelope`

```rust
pub async fn verify_inbound_envelope(&self, e: &Envelope) -> Result<(), ClientError>
```

Verifies an *inbound* envelope's signature, resolving the sender's key
via the same index/resolve machinery `call_tool` uses. `sdk/go` has no
equivalent — Go code in that module reaches `internal/envelope` +
`internal/identity` directly for the same check. A receiving node built
on this crate uses this instead of hand-rolling the same crypto.

## Delegating: `sign_delegation_link`, `delegation::verify`

```rust
pub fn sign_delegation_link(&self, delegate: &str, scope: Scope,
    expires: SystemTime, nonce: &str) -> Result<Link, ClientError>
```

Builds and signs one core §2.5 link with this `Client` as the
**delegator** — call this on the identity granting authority, not the
one receiving it. `nonce` should be a fresh `envelope::new_id()` per
link. A root link (the first in a chain) with an entirely empty scope
and no short expiry is rejected by verifiers per core §2.5 rule 5.

Unlike `sdk/go` (signing only — verification is Go-side,
`internal/delegation.Verify`, unreachable from Rust), this crate also
implements the **verifier**:

```rust
pub fn verify(input: &VerifyInput) -> Result<(), RuleViolation> // awp::delegation
```

All 7 core §2.5 rules, each returning a `RuleViolation` naming the
specific rule and link index — never a generic error. A receiving node
validating an inbound `AWP-Delegation` header calls this directly, or
via `httpsig`'s own request verification (below), which already calls
it internally.

## The RFC 9421 subset: `httpsig`

The exact same 7-step algorithm `internal/httpsig` implements in Go and
`sdk/python`'s `httpsig` module implements independently
(`awp-sig-v0.1.md`): `@method`, `@target-uri`, a `content-digest` when
there's a body, and every `AWP-*` header present — no negotiation, one
way to build and one way to verify a signature. `call_tool` uses the
signing/response-verification halves internally; a receiving node's own
sync endpoint uses the request-verification half the same way
`internal/daemon.serveToolCall` does in Go. `tests/vectors.rs` checks
this module's output against every fixture in `testdata/awp-sig/`
byte-for-byte, not just "does it accept a valid signature."

## Error handling

Every fallible method returns `Result<_, ClientError>` — a `thiserror`
enum with one variant per failure class (index fetch, signature
mismatch, pin mismatch, tool-call rejection with the provider's
`{code, detail}` attached, etc.), richer than `sdk/go`'s single wrapped
`error` string but without `sdk/python`'s several independent exception
types — a middle point dictated by what's idiomatic in each language,
not a difference in what's actually detected.

## Where to go next

- `sdk/rust/README.md` — module-by-module layout, the known
  `revoked`-instant spec gap shared with `sdk/go`.
- `sdk/rust/tests/` — `roundtrip.rs` (sign/verify + tamper-detection for
  every field, including the newer capabilities/versioning/transactions
  additions), `client_integration.rs` (a real mock-server end-to-end,
  including `AWP-Dry-Run`/`AWP-Transaction` header assertions),
  `vectors.rs` (the shared `awp-sig` conformance fixtures),
  `jcs_crosscheck.rs` (canonicalization vs. real `gowebpki/jcs` bytes).
- [`docs/sdk-go.md`](sdk-go.md), [`docs/sdk-python.md`](sdk-python.md) —
  the other two SDKs; all three implement the identical wire contract,
  and reading them side by side is the fastest way to see exactly where
  a from-scratch reimplementation (Rust, Python) needs more code than a
  same-module wrapper (Go) does.
- [`docs/protocol-overview.md`](protocol-overview.md) — the concepts
  these methods implement.
