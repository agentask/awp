# `sdk/go` — the AWP Go SDK

```go
import awp "github.com/agentask/awp/sdk/go"
```

This is the one package in this repo meant for third-party programs.
Everything else under `internal/` is off-limits outside this module by
Go's own visibility rules; `sdk/go` is the deliberately public surface
that wraps just enough of it to sign, send, call, and verify.

## Thin, on purpose

`awp.Client` keeps **no on-disk state**, runs **no retry/outbox state
machine**, and **does not receive envelopes** on its own. Compare:

| | `sdk/go.Client` | `cmd/awpd` (`internal/daemon.Daemon`) |
|---|---|---|
| Sending an envelope | one signed POST, and that's it | signs, persists, retries with backoff until TTL, dead-letters |
| Calling a tool | one signed request/response | (not its job — a daemon doesn't call tools, it serves them) |
| Receiving envelopes | not supported | runs an inbox, a gate, and a processing loop |
| Index/key cache | in-memory, per-process | bbolt-backed, with rotation-continuity checks across restarts |

If you need retry, persistence, or an inbox, run `cmd/awpd` and either
drive it as a library (`internal/daemon.Daemon`, since your program is
inside this module) or run it as a separate process and talk to it. If
you just want to sign one thing and send it, this SDK is the whole
answer — see `examples/hello-tool`, `examples/stateful-tool-delegation`,
and `examples/portable-wasm-tool`, all of which use nothing but this
package on the calling side.

## `Client`

```go
type Client struct {
	Domain string             // this client's own identity
	Kid    string             // and its active signing key id
	Priv   ed25519.PrivateKey

	HTTP *http.Client                  // nil = http.DefaultClient
	IndexURL func(domain string) string // nil = "https://" + domain + "/.well-known/awp.json"
}
```

`Domain`/`Kid`/`Priv` are only needed for methods that sign something
(`SendEnvelope`, `CallTool`, `SignDelegationLink`). Read-only methods
(`FetchIndex`, `FetchManifest`, `Resolve`) work on a zero-value `Client`
with just `HTTP`/`IndexURL` set — see `examples/portable-wasm-tool` for
exactly that: a caller that never signs anything because it only fetches
a manifest and runs a binary locally.

`IndexURL` exists for local/test use — pointing a known domain at a real
`httptest.Server` instead of real DNS — the same substitution every
example in this repo makes. Leave it `nil` in production; the default is
core §1.1's own rule (`https://{domain}/.well-known/awp.json`).

A `Client`'s index cache is populated lazily and kept for the process's
lifetime; call `Refresh` to force a re-fetch. All methods are safe for
concurrent use.

## Reading: `FetchIndex`, `Resolve`, `FetchManifest`

```go
func (c *Client) FetchIndex(ctx context.Context, domain string) (*identity.Index, error)
func (c *Client) Resolve(domain, kid string) (ed25519.PublicKey, error)
func (c *Client) FetchManifest(ctx context.Context, principal string) (*manifest.Manifest, error)
func (c *Client) Refresh(domain string) error
```

`FetchIndex` fetches and verifies a domain's self-signature (TOFU: the
first fetch trusts whichever key the index names). `Resolve` looks up a
specific key within an already-fetched-or-fetched-on-demand index, and
also makes `*Client` satisfy `internal/httpsig.KeyResolver` and
`internal/delegation.KeyResolver` directly — you can pass a `*Client` as
the resolver argument to either package's `Verify` if you're validating
something the SDK itself received (e.g. `CallTool` passes `c` to
`httpsig.VerifyResponse` internally, for exactly this reason).

`FetchManifest` fetches a manifest, checks its `sha256` pin against the
owning domain's index (core §1.2 — before the signature, so a swapped
manifest is caught by the cheaper check first), then verifies its
signature. Use it directly when you need a manifest without making a
sync call against it — the only way to reach a `distribution.portable`
tool, since those don't have a callable endpoint at all:

```go
m, err := client.FetchManifest(ctx, "wasm-tool.example#wordcount")
// m.Distribution.Portable.URL / .Sha256 — download and run it yourself.
```

## Sending: `SendEnvelope`

```go
func (c *Client) SendEnvelope(ctx context.Context, kind, to, thread string,
	inReplyTo *string, body json.RawMessage, ttl int) (*envelope.Envelope, error)
```

Builds, signs, and POSTs one envelope to `to`'s resolved inbox — one
delivery attempt, synchronously. `ttl` of `0` defaults to 3600s;
`inReplyTo` may be `nil` for a thread opener. Minting a fresh thread id
is the caller's job (core §2.1: "ULID minted by the sender of the
thread's first envelope") — use `envelope.NewID()`:

```go
thread := envelope.NewID()
env, err := client.SendEnvelope(ctx, "message", "bob.example", thread, nil,
	json.RawMessage(`{"type":"text","text":"hi"}`), 3600)
```

A non-2xx response returns an error with the response body attached; the
SDK does not retry. See `examples/agent-messaging` for the full
`message → ack → reply → close` cycle — note that in that example both
sides run a full `daemon.Daemon` (so they can *receive*), and the
`Send`/delivery loop shown there is `internal/daemon`'s own equivalent of
this method, not the SDK's — `sdk/go` has no receiving story at all.

### Streaming a response: `SendStreamChunk`

```go
func (c *Client) SendStreamChunk(ctx context.Context, kind, to, thread string,
	inReplyTo *string, streamID string, seq int, final bool,
	data json.RawMessage, ttl int) (*envelope.Envelope, error)
```

A thin wrapper over `SendEnvelope` with `awp-streaming-v0.1.md` §2's
body shape (`{"type":"stream_chunk","stream_id",...}`) built for you —
same single-delivery-attempt behavior, same lack of retry. `streamID` is
a fresh `envelope.NewID()` for `seq: 0` of a new stream, then the same
value for every later chunk of that stream; `seq` must strictly
increase; `final` is `true` on exactly the last chunk. This SDK has no
receiving story (see above), so it only ever sends chunks — reassembly
on the far end is `internal/daemon`'s `Config.StreamChunkHandler`
(`docs/agent-guide.md`'s "Receiving a streamed answer").

```go
thread := envelope.NewID()
streamID := envelope.NewID()
client.SendStreamChunk(ctx, "reply", "bob.example", thread, nil, streamID, 0, false, json.RawMessage(`{"text":"first chunk"}`), 3600)
client.SendStreamChunk(ctx, "reply", "bob.example", thread, nil, streamID, 1, true, json.RawMessage(`{"text":"last chunk"}`), 3600)
```

## Calling: `CallTool`

```go
type CallOptions struct {
	Session    string            // an AWP-Session token from a prior call, or ""
	Delegation []delegation.Link // a pre-signed core §2.5 chain, or nil
}

type SessionInfo struct {
	Token, Sid, Expires string
}

func (c *Client) CallTool(ctx context.Context, toolPrincipal string,
	input json.RawMessage, opts CallOptions) (json.RawMessage, *SessionInfo, error)
```

Resolves `toolPrincipal`'s manifest, requires
`Distribution.Hosted != nil` (portable-only tools aren't callable this
way — use `FetchManifest` instead), signs the request per `awp-sig`, and
sends it. If the provider signs its response (awp-sig §3, `SHOULD`), the
signature is verified before the response is trusted — **a
present-but-invalid response signature is an error; an absent one is
not**, per spec.

```go
output, session, err := client.CallTool(ctx, "calc.example#multiply",
	json.RawMessage(`{"a":6,"b":7}`), awp.CallOptions{})
```

`session` is non-nil exactly when the tool is `state: provider` and this
call didn't already present a valid one — pass `session.Token` back as
`CallOptions.Session` on the next call to the same tool:

```go
_, session, _ := client.CallTool(ctx, tool, input, awp.CallOptions{})
// ... later, same caller, same tool:
out, _, err := client.CallTool(ctx, tool, input2, awp.CallOptions{Session: session.Token})
```

To call on someone else's behalf, attach a delegation chain — see
`SignDelegationLink` below and `examples/stateful-tool-delegation` for
the full three-party version (an org delegates to an employee; the tool
attributes the call to the org).

```go
out, _, err := employee.CallTool(ctx, tool, input, awp.CallOptions{
	Delegation: []delegation.Link{link},
})
```

## Delegating: `SignDelegationLink`

```go
func (c *Client) SignDelegationLink(delegate string, scope delegation.Scope,
	expires time.Time, nonce string) (delegation.Link, error)
```

Builds and signs one core §2.5 link with this `Client` as the
**delegator** — i.e. call this on the identity granting authority, not
the one receiving it:

```go
scopedTo := "notes.example#counter"
link, err := acme.SignDelegationLink("employee.example",
	delegation.Scope{To: &scopedTo}, time.Now().Add(time.Hour), envelope.NewID())
```

`nonce` should be a fresh `envelope.NewID()` per link. A root link (the
first in a chain) with an entirely empty scope and no short expiry is
rejected by verifiers per core §2.5 rule 5 — always set at least one
scope field, or keep `expires` within 24h, on a root link.

Chaining multiple links (a delegates to b, b delegates to c) is just
calling `SignDelegationLink` again with `b`'s own `Client` as the
delegator and assembling the resulting links, root first, into one
`[]delegation.Link` slice — `internal/delegation.Verify` (run server-side
inside `CallTool`'s target, via `internal/httpsig.Verify`) checks
continuity between links for you; the SDK doesn't need its own
chain-building helper beyond signing one link at a time.

## Error handling

Every SDK method returns a plain Go `error` wrapping context about what
failed — network errors, signature/pin verification failures, and
provider-returned `{code, detail, retryable}` bodies (core §2.6) are all
folded into the error string rather than a typed error value. If you
need to branch on the provider's specific error code, parse the
provider's response yourself (the same `apperr.Body` shape `CallTool`
already decodes internally) — this SDK deliberately keeps its error
surface to "did it work," matching its "thin" scope; a typed error
hierarchy is exactly the kind of API growth that would blur the
daemon/SDK boundary this document opened with.

## Where to go next

- `examples/` — every method above, used in a complete, runnable program.
- [`docs/agent-guide.md`](agent-guide.md) — the decisions an AI agent's
  own reasoning loop makes around these calls (what to feed a model,
  when a call needs delegated authority, session reuse across a task).
- [`docs/architecture.md`](architecture.md) — what happens on the other
  end of each of these calls.
- [`docs/protocol-overview.md`](protocol-overview.md) — the concepts
  these methods implement.
