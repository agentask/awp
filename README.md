i# AWP — Agent Web Protocol

An open protocol for an internet of AI agents: agent-to-agent communication and
publishing capabilities (tools, apps, agents) for other agents to discover and
consume. Federated by design — anyone hosts, names resolve through DNS, no
central registry, no new PKI.

## Design decisions (ratified)

| Decision            | Choice                                                        |
|---------------------|---------------------------------------------------------------|
| Shape               | Open protocol + Go reference platform (`awpd`)                |
| Primitives          | Layered: tools (sync), apps (sessions), agents (async A2A)    |
| Discovery / trust   | Federated, DNS-anchored; crawlable format, competitive indexes|
| Identity            | Domain-anchored Ed25519 keys, DKIM-style, rotation chains     |
| Economics           | Deferred; `pricing` field reserved (`null` in v0.1)           |
| Transport           | Sync signed HTTPS for tools; async signed inboxes for A2A     |
| Publishing artifact | Signed manifest; hosted endpoint and/or portable WASM         |
| Session state       | Negotiated per-entity in manifest (`stateless`/`provider`/`caller`) |
| Oversight           | Minimal: request signing + delegation proofs; content trust is the client's problem |

## Layer model

```
L3  Semantics   tools · apps · agent threads
L2  Manifest    signed capability documents
L1  Wire        signed HTTPS (sync) + inboxes (async)
L0  Naming      DNS + .well-known + domain keys
```

## Documents

| File                       | Status | Scope                                        |
|----------------------------|--------|----------------------------------------------|
| `spec/awp-core-v0.1.md`    | Draft  | Normative protocol: L0–L3                    |
| `spec/awp-sig-v0.1.md`     | Draft  | Normative sync signing profile (RFC 9421)    |
| `spec/awp-discovery-v0.1.md` | Strawman | Index query/submission schema (post-M1 validation) |
| `spec/awp-quic-v0.1.md`    | Draft  | Optional `awp/1` QUIC binding + `awp://` scheme |
| `spec/awpd-store-v0.1.md`  | Draft  | `awpd` only: persistence layout (bbolt)      |
| `spec/awpd-outbox-v0.1.md` | Draft  | `awpd` only: delivery retry state machine    |

The two `awpd-*` documents are implementation specs for the reference daemon.
They are NOT normative for the protocol; alternative implementations may
persist and retry however they like as long as the observable wire behavior
in `awp-core` and `awp-sig` holds.

## Reference implementation

`awpd` — single Go binary: serves the domain index, inbox, and hosted tools;
runs portable entities on wazero; ships an `awp` CLI (`keys`, `publish`,
`call`, `send`, `outbox`). First milestone: two instances completing a signed
`message → reply → close` thread on localhost.

## v0.2 backlog (deliberately out of scope for v0.1)

Multiparty threads · store-and-forward relays · WASM component-model (WIT)
interface · pricing/settlement · standardized scope vocabulary ·
content-trust/provenance beyond sender authentication. (`awp/1` over QUIC
moved into v0.1 as an optional binding: `spec/awp-quic-v0.1.md`.)
