# CLI reference

Two binaries: `awpd`, the daemon, and `awp`, a small CLI for conformance
testing and local inspection. This document lists every flag either one
actually has — no aspirational subcommands. (`README.md` used to claim an
`awp` CLI with `keys`/`publish`/`call`/`send` subcommands; those don't
exist. Programmatic send/call/delegate is `sdk/go`, covered in
[`docs/sdk-go.md`](sdk-go.md).)

## `awpd`

```
go build -o awpd ./cmd/awpd
./awpd -domain example.com -kid 2026-07-01 [flags]
```

`-domain` and `-kid` are required; everything else has a default that
works for a local run.

| Flag | Default | Meaning |
|---|---|---|
| `-domain` | *(required)* | This domain's principal name. |
| `-kid` | *(required)* | This domain's active signing key id. |
| `-addr` | `127.0.0.1:8443` | HTTPS listen address. |
| `-data` | `./awpd-data` | Directory for the bbolt store and identity key file. Created if missing. |
| `-tick` | `1s` | Outbox delivery / inbound processing tick interval. |
| `-tls-cert` | *(unset)* | Path to a PEM-encoded TLS certificate — production use (e.g. Let's Encrypt, your own CA). Must be given together with `-tls-key`. |
| `-tls-key` | *(unset)* | Path to the PEM-encoded private key matching `-tls-cert`. |
| `-resolve-base-url` | *(unset)* | Override the base URL **all** domain-index resolution uses. Local/dev/self-test only — production leaves this unset and resolves `https://{domain}` per domain, per core §1.1. |
| `-resolve-insecure` | `false` | Skip TLS certificate verification when *this* daemon resolves domain indexes or dials `awp/1` peers. Local/dev/self-test only — never set this in production. |
| `-quic-addr` | *(unset)* | `awp/1` (QUIC) listen address. Empty disables QUIC entirely and the daemon advertises HTTPS-only, which is always spec-compliant (`awp-quic-v0.1.md` §2). |
| `-quic-dial-timeout` | `5s` | Timeout dialing a peer's `awp/1` endpoint before falling back to HTTPS. |
| `-ws` | `false` | Enable `awp-ws/1` (WebSocket) transport (`awp-ws-v0.1.md`). Needs no separate listen address — it shares `-addr`'s existing HTTPS listener. |
| `-ws-dial-timeout` | `5s` | Timeout dialing a peer's `awp-ws/1` endpoint before falling back to the next transport. |
| `-disable-streaming` | `false` | Reject `stream_chunk` bodies with `error(unsupported_body)` instead of reassembling them, and stop advertising the `"awp-streaming-v0.1"` capability — simulates an implementation that hasn't adopted `awp-streaming-v0.1.md` (core §2.3/§9). The default adopts streaming. |
| `-stream-buffer-max-age` | `24h` | How long an incomplete stream's reassembly buffer is kept before hourly GC reclaims it as abandoned (`awp-streaming-v0.1.md` §5). |
| `-demo-echo-tool` | `false` | Register a demo `kind:tool` entity (`#echo`) that returns its verified caller + input, for trying out sync tool calls without writing any code. Not registered by default. |
| `-dead-retention` | `720h` | How long dead-lettered outbound envelopes are kept before hourly GC deletes them (`awpd-outbox-v0.1.md` §3 `outbox.dead_retention`). |

**Identity.** On first run, `awpd` generates an Ed25519 keypair and
persists it PEM-encoded at `{data}/identity.pem`; subsequent runs reuse
it. There's no separate `awp keys` step — the daemon creates its own
identity the first time it starts.

**TLS.** `awpd` always terminates real TLS — this is core §6's mandatory
HTTPS floor, not optional. Give `-tls-cert`/`-tls-key` for anything real.
Without them, it generates (and persists, at
`{data}/tls-self-signed-{cert,key}.pem`) a self-signed certificate for
`-domain` — enough to run and test against locally, but any peer doing
real WebPKI validation will correctly reject it. That's the point of
`-resolve-insecure`: it's what lets *this daemon's own outbound client*
accept another self-signed local peer (or itself, for self-addressed
conformance runs) during local testing.

**What runs in the background.** Once started, `awpd` runs three
tickers on `-tick`/hourly cadences for as long as the process is alive:
inbound processing + outbound delivery (every `-tick`), and garbage
collection of expired `seen` entries, past-retention dead letters, and
abandoned incomplete stream reassembly buffers (hourly, per
`awpd-store-v0.1.md` §2's "GC: hourly cursor scan" and
`awp-streaming-v0.1.md` §5 — see [`docs/deployment.md`](deployment.md)
for tuning retention).

## `awp`

```
go build -o awp ./cmd/awp
```

### `awp conformance <domain> [flags]`

Runs the core §5, `awp-quic` §8, and `awp-ws` §7 conformance checklists,
plus every registered extension this repo implements (capability
advertisement, `status` entities, push/wake, transactions, streaming —
see [`docs/protocol-overview.md`](protocol-overview.md#extensions-beyond-core-v01)
for the full list), against any AWP implementation reachable at
`<domain>` — not just this repo's own `awpd`. Exits `0` if every check
passed or was a documented `Skip`, `1` if anything failed.

| Flag | Default | Meaning |
|---|---|---|
| `-base-url` | *(unset)* | Override the base URL `<domain>` resolves to — testing/local use. |
| `-key` | *(unset)* | Path to a PEM-encoded Ed25519 private key, used as this run's own signing identity for checks that need to act as a caller. |
| `-kid` | *(unset)* | Key id matching `-key`, as registered in the target's own index. Required alongside `-key`. |
| `-timeout` | `30s` | Overall run timeout. |
| `-insecure` | `false` | Skip TLS certificate verification over HTTPS — self-signed local `awpd`, dev only. |
| `-quic-insecure` | `false` | Same, when dialing the target's `awp/1` endpoint. |

```
go run ./cmd/awp conformance example.com -insecure
```

A number of checklist items (`core-5.4-delegation`,
`core-5.5-unknown-body-type`, `core-5.7-two-party`, `core-5.3-retention`,
and — for the same underlying reason — most of `awp-streaming`'s §10
items) always report `Skip` with a specific reason, not `Pass` — they
describe internal state, or an async response delivered to a receiving
inbox the prober doesn't have, neither of which a stateless black-box
prober can observe from outside. See `docs/experiments.md`'s Phase 5
section for the original reasoning; this isn't a gap in the checker,
it's a property of what's actually observable over the wire.

### `awp outbox ls -dead -data <dir>`

Lists dead-lettered outbound envelopes from a local `awpd` data
directory (read-only; safe to run against a live daemon's data
directory without stopping it — it opens the bbolt store read-only).

| Flag | Default | Meaning |
|---|---|---|
| `-dead` | `false` | List only dead-lettered records. Currently the only supported mode — `ls` without it is an error. |
| `-data` | `./awpd-data` | The `awpd` data directory to read. |

```
go run ./cmd/awp outbox ls -dead -data ./awpd-data
```

```
01k....  state=dead_expired   attempts=7   reason=ttl expired before delivery succeeded
(no dead-lettered envelopes)   # when there are none
```

## Where to go next

- [`docs/deployment.md`](deployment.md) — running two real domains, TLS
  cert setup, enabling QUIC, tuning retention.
- [`docs/getting-started.md`](getting-started.md) — the examples that
  don't need either binary at all (they embed `internal/daemon` directly).
