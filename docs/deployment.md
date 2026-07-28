# Deployment

Running `awpd` for a real domain, instead of a local demo. Everything
here builds on [`docs/cli-reference.md`](cli-reference.md) — read that
first for what each flag does; this document is about how they fit
together for a production-shaped setup.

## 1. DNS and `.well-known`

AWP has no separate registration step. A domain participates the moment
it serves a valid signed index at `https://{domain}/.well-known/awp.json`
(core §1.1). Concretely:

1. Point `example.com` (or a subdomain) at wherever `awpd` will run.
2. Put a TLS-terminating endpoint in front of it that reaches `awpd`'s
   `-addr` — either give `awpd` a real certificate directly
   (`-tls-cert`/`-tls-key`) or terminate TLS at a reverse proxy/load
   balancer and forward plain HTTP to `-addr` internally. `awpd` itself
   has no concept of "behind a proxy" — pick one of these two shapes.
3. Once it's reachable, `curl https://example.com/.well-known/awp.json`
   should return the signed index. That's the whole bootstrap: any peer
   resolving `example.com` from this point on does exactly that request.

There is no step 4 — no index to register with, no central registry to
notify. The domain *is* the registration.

## 2. TLS certificates

```
awpd -domain example.com -kid 2026-07-01 \
  -tls-cert /etc/awpd/fullchain.pem -tls-key /etc/awpd/privkey.pem
```

Give `awpd` a real certificate (Let's Encrypt, your existing CA,
whatever your fleet already uses) via `-tls-cert`/`-tls-key`. Both are
required together — `awpd` refuses to start with only one set.

**Without them**, `awpd` generates and persists a self-signed
certificate (`{data}/tls-self-signed-{cert,key}.pem`) and starts anyway.
This is the local-demo path every `examples/` program uses — it's
correct behavior for `go run ./examples/hello-tool`, but it means a
daemon started with no flags at all is silently running on a certificate
no real peer will trust. There's no runtime error for this — a peer
attempting real WebPKI validation just gets a TLS handshake failure, and
you have to notice. Always pass `-tls-cert`/`-tls-key` outside a demo.

`-resolve-insecure` is the corresponding escape hatch for *this daemon's
own outbound client* — it lets it accept another self-signed peer (or
itself, for self-addressed conformance runs) during local testing. Never
set it in production: it disables certificate validation for every
domain this daemon resolves, not just the one you're testing against.

## 3. Enabling `awp/1` (QUIC)

QUIC is an optional, negotiated upgrade (`awp-quic-v0.1.md`) — never a
replacement for HTTPS, which remains mandatory regardless:

```
awpd -domain example.com -kid 2026-07-01 \
  -tls-cert ... -tls-key ... \
  -quic-addr example.com:8443 -quic-dial-timeout 5s
```

With `-quic-addr` set, `awpd` listens for `awp/1` on that address
(reusing the same TLS certificate) and advertises it in its own signed
index's `transports[]`. Peers that also speak `awp/1` may use it for
envelope delivery; peers that don't (or a QUIC attempt that fails) get
HTTPS, transparently — `internal/quictrans.FallbackSender` is what makes
a failed QUIC attempt fall back to the exact same HTTPS delivery path,
and the receiving gate is identical either way
(`internal/inbox.Gate` is transport-blind; see
[`docs/architecture.md`](architecture.md)).

Leaving `-quic-addr` unset (the default) is not a degraded mode — an
index with no `transports[]` entry is HTTPS-only, which is always
spec-compliant.

## 3.5. Enabling `awp-ws/1` (WebSocket)

`awp-ws-v0.1.md`'s WebSocket transport is the same kind of optional,
negotiated upgrade QUIC is — but unlike QUIC, it needs no separate
listen address or certificate; it shares `-addr`'s existing HTTPS
listener:

```
awpd -domain example.com -kid 2026-07-01 \
  -tls-cert ... -tls-key ... \
  -ws -ws-dial-timeout 5s
```

With `-ws` set, `awpd` mounts the WebSocket upgrade handler on its
existing mux and advertises `transports: [{"proto":"awp-ws/1", ...}]`.
Fallback and gate equivalence work identically to QUIC's — a failed
handshake or connection falls back to HTTPS with the exact same bytes
(`internal/wstrans.FallbackSender`), and `internal/inbox.Gate` doesn't
know or care which transport handed it an envelope. If both `-quic-addr`
and `-ws` are set, this daemon's own outbound sends try WebSocket, then
`awp/1`, then HTTPS, in that order (`awp-ws-v0.1.md` §5's reference
ordering) — an operator enabling both isn't choosing between them, a
sender picks per attempt.

## 4. Retention and garbage collection

`awpd` runs GC on an hourly ticker automatically — there's no flag to
disable it, only to size the three things it collects:

- **`seen` entries** (the dedupe set for inbound envelope ids) are
  deleted once their retention window passes. This is sized per-envelope
  by that envelope's own `ttl`, per core §4's replay-defense rule
  ("receivers MUST retain seen-ids ≥ the longest TTL they accept") — not
  independently configurable; raise the TTLs you accept if you need a
  longer replay-defense window.
- **Dead-lettered outbound records** are deleted after
  `-dead-retention` (`awpd-outbox-v0.1.md` §3's `outbox.dead_retention`,
  defaulting to 720h / 30 days). Embedding `internal/daemon` directly
  instead of running the `awpd` binary sets the same value via
  `Config.DeadRetention`.
- **Incomplete stream reassembly buffers** (`awp-streaming-v0.1.md` §5 —
  a stream that never received its `final: true` chunk) are reclaimed
  after `-stream-buffer-max-age` (defaulting to 24h) with no new chunk
  arriving. A *completed* stream's tiny leftover bookkeeping record is
  reclaimed the same way, on the same timer — there's nothing costly
  about it either way. `Config.StreamBufferMaxAge` is the same knob when
  embedding `internal/daemon` directly.

Inspect what's currently dead-lettered at any time, without stopping the
daemon:

```
awp outbox ls -dead -data ./awpd-data
```

An envelope dead-letters when its TTL expires before delivery succeeds,
or the destination returns a non-`429` `4xx` (core §2.2: "on `4xx` other
than `429`: stop, the envelope is dead. There is no relay tier in v0.1").
A growing dead-letter count is always worth investigating — it means a
peer is unreachable, misconfigured, or actively rejecting you, not that
retries are still quietly working in the background.

## 5. Running two real domains — a checklist

Everything `examples/agent-messaging` does in-process, for real:

1. Each domain runs its own `awpd`, own `-data` directory, own real TLS
   certificate.
2. Each resolves the other purely by fetching
   `https://{their-domain}/.well-known/awp.json` — no shared
   configuration, no allowlist, no introduction step. If domain A can
   already resolve B's index (steps 1–2 above are satisfied for both),
   A can already send B a `message` and get an `ack`/`reply` back.
3. Watch each daemon's own logs for delivery/GC activity; there's no
   cross-daemon dashboard in this reference implementation.
4. Run `awp conformance {domain}` against either one from outside to
   verify it independently — this is the same check any third-party
   implementation would run against you, not just this repo's own binary.

## 6. What this reference daemon doesn't do for you

- **No process supervision.** `awpd` doesn't daemonize, fork, or manage
  its own restarts — run it under systemd, a container orchestrator, or
  whatever your fleet already uses. Crash recovery on restart *is*
  handled (`internal/store`'s `BootRecovery`/`InboundBootRecovery` move
  any in-flight work back to a clean queued state), so restarting it is
  always safe; it just isn't automatic.
- **No horizontal scaling story.** One `awpd` process owns one bbolt
  file for one domain. Running more than one instance for the same
  domain against the same data directory is not supported.
- **No message-handling customization via flags.** `internal/daemon.Config.MessageHandler`
  is a real Go function value — there's no way to hand one over on the
  command line, so real application logic still means embedding
  `internal/daemon` as a library in your own program rather than running
  the `awpd` binary unmodified. The `awpd` binary itself always uses the
  reference default (ack, then a fixed reply). See
  `examples/custom-message-handler` for what setting `MessageHandler`
  actually looks like, and `docs/agent-guide.md`'s "being called"
  section for when you need to.

## Where to go next

- [`docs/cli-reference.md`](cli-reference.md) — every flag referenced
  above, in full.
- [`docs/architecture.md`](architecture.md) — what's actually running
  inside the ticks and gates this document assumes.
