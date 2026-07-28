# `sdk/python` — the AWP Python SDK

```python
from awp import client, identity, manifest, delegation, httpsig, bootstrap
```

Managed with `uv`; see `sdk/python/README.md` for install/test commands.
This is a from-scratch Python reimplementation of the signing/envelope/
manifest logic `internal/*` implements in Go — not a wrapper around it.
Python can't import Go's `internal/` packages the way `sdk/go` does (same
module, same language), so this package carries its own JCS
canonicalization, Ed25519 signing, RFC 9421 subset, and delegation-chain
verification, independently implemented and cross-checked against the Go
implementation for byte-identical output (see "Where to go next").

## Thinner in one sense, more complete in another

Like `sdk/go`, `Client` keeps **no on-disk state**, runs **no
retry/outbox state machine**, and **does not receive envelopes on its
own** — same "thin" scope, same reasoning: if you need persistence,
retry, or a real inbox, run `cmd/awpd` (or an `internal/daemon.Daemon`
embedded in a Go program) instead.

But this package carries more than `sdk/go` does in one specific way:
`sdk/go`'s Go programs can `import "github.com/agentask/awp/internal/..."`
directly for anything receiver-side (signature verification, delegation
chain checking) since it's the same module. Python has no such
`internal/` to reach into, so **this package includes the verification
logic too** — `delegation.verify` (all 7 core §2.5 rules, not just
signing one link), `httpsig.verify_request`/`verify_response` (the full
server-side RFC 9421 subset algorithm), and `Client.verify_inbound_envelope`
— everything a from-scratch Python *receiving* node needs, not just a
calling one. `agents/python/concierge` is such a node, built entirely on
this package.

## `Client`

```python
Client(domain: str, kid: str, priv: Ed25519PrivateKey, *,
       http: httpx.Client | None = None,
       index_url: Callable[[str], str] | None = None)
```

`domain`/`kid`/`priv` are only needed for methods that sign something
(`send_envelope`, `call_tool`, `sign_delegation_link`). `index_url`
overrides where a domain's index is fetched from — local/test use,
pointing a known domain at a real local server instead of DNS; every
test in `sdk/python/tests/` makes this substitution via `httpx`'s mock
transport rather than a real socket. Leave it unset in production; the
default is core §1.1's own rule
(`https://{domain}/.well-known/awp.json`).

A `Client`'s index cache is populated lazily and kept for the instance's
lifetime; call `.refresh(domain)` to force a re-fetch.

## Reading: `fetch_index`, `resolve`, `fetch_manifest`

```python
def fetch_index(self, domain: str) -> identity.Index
def resolve(self, domain: str, kid: str) -> Ed25519PublicKey
def fetch_manifest(self, principal: str) -> manifest.Manifest
```

`fetch_index` fetches and verifies a domain's self-signature (TOFU: the
first fetch trusts whichever key the index names). `resolve` looks up a
specific key within an already-fetched-or-fetched-on-demand index —
`Client` implements `httpsig.KeyResolver` directly (`resolve_key`/
`refresh_key_domain`), so you can pass a `Client` anywhere that protocol
is expected, e.g. `httpsig.verify_response` inside `call_tool` uses `self`
this exact way.

`fetch_manifest` checks the `sha256` pin against the owning domain's
index (core §1.2 — before the signature, so a swapped manifest is caught
by the cheaper check first), then verifies the signature. Use it
directly for a `distribution.portable` tool — the only way to reach one,
since it has no callable endpoint at all:

```python
m = client.fetch_manifest("wasm-tool.example#wordcount")
# m.distribution.portable.url / .sha256 — download and run it yourself.
```

## Sending: `send_envelope`, `send_stream_chunk`

```python
def send_envelope(self, kind: str, to: str, thread: str,
                   in_reply_to: str | None, body: Any, ttl: int = 0) -> Envelope
```

Builds, signs, and POSTs one envelope to `to`'s resolved inbox — one
delivery attempt, synchronously. `ttl` of `0` defaults to 3600s. Minting
a fresh thread id is the caller's job (core §2.1: "ULID minted by the
sender of the thread's first envelope") — use `envelope.new_id()`:

```python
thread = envelope.new_id()
env = client.send_envelope("message", "bob.example", thread, None, {"type": "text", "text": "hi"})
```

```python
def send_stream_chunk(self, to: str, thread: str, in_reply_to: str | None,
                       stream_id: str, seq: int, final: bool, data: Any,
                       kind: str = "reply", ttl: int = 0) -> Envelope
```

A thin wrapper over `send_envelope` with `awp-streaming-v0.1.md` §2's
body shape built for you. `kind` defaults to `"reply"` (the spec's own
"typically reply"); `stream_id` is a fresh `envelope.new_id()` for
`seq: 0` of a new stream, then the same value for every later chunk;
`seq` must strictly increase; `final` is `True` on exactly the last
chunk. Producer-side only — this package's statelessness means it has no
reassembly story on purpose; a receiving daemon
(`internal/daemon`'s `Config.StreamChunkHandler`) does that buffering.

```python
stream_id = envelope.new_id()
client.send_stream_chunk("bob.example#agent", thread, None, stream_id, 0, False, {"text": "first chunk"})
client.send_stream_chunk("bob.example#agent", thread, None, stream_id, 1, True, {"text": "last chunk"})
```

## Calling: `call_tool`

```python
@dataclass
class CallOptions:
    session: str = ""
    delegation: list[delegation.Link] | None = None
    dry_run: bool = False
    transaction: Transaction | None = None

def call_tool(self, tool_principal: str, input: Any,
               opts: CallOptions | None = None) -> tuple[Any, SessionInfo | None]
```

Resolves `tool_principal`'s manifest, requires a `hosted` distribution
(portable-only tools aren't callable this way — use `fetch_manifest`
instead), signs the request per `awp-sig`, and sends it. If the provider
signs its response (awp-sig §3, `SHOULD`), the signature is verified
before the response is trusted — a present-but-invalid response
signature is an error; an absent one is not.

```python
output, session = client.call_tool("calc.example#multiply", {"a": 6, "b": 7})
```

`session` is not `None` exactly when the tool is `state: provider` and
this call didn't already present a valid one — pass `session.token` back
as `CallOptions.session` on the next call to the same tool.

`dry_run` and `transaction` are both ordinary `AWP-*` headers — nothing
in `httpsig.sign_request`'s covered-component logic needed to change to
add either, and neither did on the wire-format side. Both are advisory:
a provider that never declared support MAY ignore either silently
rather than reject the call.

```python
@dataclass
class Transaction:
    id: str
    step: int
    coordinator: str
```

`Transaction` is the saga-coordination primitive from
`awp-transactions-v0.1.md` — see that document's §0 for why AWP models
multi-tool coordination as compensating actions rather than two-phase
commit. This SDK only signs and sends the header; the coordinator-side
retry/compensate algorithm (the spec's §3) is the caller's own logic.

```python
client.call_tool("invoice-tool.example#generate", input, client_mod.CallOptions(dry_run=True))
client.call_tool(tool, input, client_mod.CallOptions(
    transaction=client_mod.Transaction(id=txn_id, step=0, coordinator=caller.domain),
))
```

To call on someone else's behalf, attach a delegation chain — see
"Delegating" below.

```python
output, _ = employee.call_tool(tool, input, client_mod.CallOptions(delegation=[link]))
```

## Verifying inbound envelopes: `verify_inbound_envelope`

```python
def verify_inbound_envelope(self, env: Envelope) -> None
```

Verifies an *inbound* envelope's signature, resolving the sender's key
via the same index/resolve machinery `call_tool` uses — retries once
after a `Client.refresh` on the sender's domain if the first attempt
fails, per core §0.1's rotation-race rule. `sdk/go` has no equivalent
method: Go code in this module reaches `internal/envelope` +
`internal/identity` directly for the same check. A receiving node built
on this SDK (e.g. `agents/python/concierge`) uses this instead of
hand-rolling the same crypto.

## Delegating: `sign_delegation_link`, `delegation.verify`

```python
def sign_delegation_link(self, delegate: str, scope: delegation.Scope,
                           expires: float, nonce: str) -> delegation.Link
```

Builds and signs one core §2.5 link with this `Client` as the
**delegator** — call this on the identity granting authority, not the
one receiving it. `expires` is a unix timestamp; `nonce` should be a
fresh `envelope.new_id()` per link.

```python
link = acme.sign_delegation_link("employee.example", delegation.Scope(to="notes.example#counter"),
                                   time.time() + 3600, envelope.new_id())
```

A root link (the first in a chain) with an entirely empty scope and no
short expiry is rejected by verifiers per core §2.5 rule 5 — always set
at least one scope field, or keep `expires` within 24h, on a root link.

Unlike `sdk/go` (which only signs — verification happens Go-side via
`internal/delegation.Verify`, unreachable from Python), this package
also implements the **verifier**:

```python
def verify(inp: VerifyInput) -> None  # awp.delegation
```

All 7 core §2.5 rules (signature, continuity, expiry, final-delegate
match, scope intersection, chain length ≤ 8, root-scope bound), each
raising `delegation.RuleViolation` with the specific rule identified —
never a generic "invalid." A receiving node validating an inbound
`AWP-Delegation` header calls this directly, or via
`httpsig.verify_request` (below), which already calls it as part of its
own step 6.

## The RFC 9421 subset: `awp.httpsig`

```python
def sign_request(*, method, url, headers, body, priv, key_id) -> dict[str, str]
def verify_request(request, body, now, deps: VerifyDeps) -> VerifyResult
def sign_response(...) -> dict[str, str]
def verify_response(*, status, headers, body, now, resolve_key) -> VerifyResponseResult
```

The exact same 7-step algorithm `internal/httpsig` implements in Go
(`awp-sig-v0.1.md`): `@method`, `@target-uri`, a `content-digest` when
there's a body, and every `AWP-*` header present — no negotiation, one
way to build and one way to verify a signature. `call_tool` uses
`sign_request`/`verify_response` internally; a receiving node's own sync
endpoint (a `kind: tool` this program serves, not calls) uses
`verify_request` the same way `internal/daemon.serveToolCall` does in Go.

## Bootstrapping a demo identity: `awp.bootstrap`

```python
def new_domain_identity(domain: str, kid: str = "k1") -> tuple[Ed25519PrivateKey, identity.Index]
def finalize_index(idx, priv, kid, inbox_url: str) -> None
def new_manifest(name, *, kind, version, description, state, endpoint=None, ...) -> manifest.Manifest
```

Generates a fresh keypair, a self-signed `Index` naming it, and (once
you sign it) a `Manifest` — enough to mint a `*.local` identity and serve
`/.well-known/awp.json` for a demo program, without hand-rolling any of
the crypto in `identity.py`/`manifest.py` yourself. Every test fixture
and demo agent in `agents/python/` uses this rather than constructing
`Index`/`Manifest` field-by-field. `finalize_index` sets the real inbox
URL and re-signs once the node's own HTTP server is listening — the same
two-step pattern `internal/daemon.New` + `FinalizeIndex` follows in Go.

## Error handling

`identity.BadSignatureError`, `manifest.PinMismatchError`,
`delegation.RuleViolation`, and `client.RemoteRejectedError`/
`client.ToolCallError` are the specific exception types this package
raises — narrower and more numerous than `sdk/go`'s single wrapped
`error` string, since Python's exception model makes `except SpecificError`
cheap in a way Go's string-wrapped errors aren't. `ToolCallError` carries
the provider's `{code, detail}` directly (`.code`/`.detail` attributes)
rather than requiring you to re-parse the response body yourself.

## Where to go next

- `sdk/python/tests/` — every method above, exercised against a mock
  `httpx` transport standing in for a real peer.
- `agents/python/concierge` — a complete receiving node built entirely
  on this package (not `internal/daemon`), using `verify_inbound_envelope`,
  `delegation.verify`, and `httpsig.verify_request` for real.
- [`docs/agent-guide.md`](agent-guide.md) — the decisions an AI agent's
  own reasoning loop makes around these calls.
- [`docs/protocol-overview.md`](protocol-overview.md) — the concepts
  these methods implement.
- [`docs/sdk-go.md`](sdk-go.md) — the Go counterpart; read together, the
  two documents' differences (verification logic here, none there) are
  entirely explained by which language can `import "internal/..."`.
