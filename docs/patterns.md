# Recommended patterns

Non-normative. Everything here is a convention — a suggested way to use
primitives that already exist (or, for `status`/`received`, primitives
registered in `spec/awp-kinds-v0.1.md`) — not a wire-format rule.
Nothing in this document can make an implementation non-conforming;
`spec/*.md` is where those rules live. If something here turns out to
need real protocol support (a new field, a new required behavior), it
belongs in `ideas/` first, the way `spec/awp-streaming-v0.1.md` and
`spec/awp-kinds-v0.1.md` both started there.

## Self-service usage/quota reporting

A provider that wants callers to be able to check their own usage
against a quota doesn't need any new protocol mechanism — this is fully
expressible today as an ordinary `kind: tool` entity, using the session
machinery that already exists (core §1.3).

```json
{
  "name": "provider.example#usage",
  "kind": "tool",
  "state": "provider",
  "io": {
    "output": {
      "type": "object",
      "properties": {
        "used": { "type": "integer" },
        "limit": { "type": "integer" },
        "resets_at": { "type": "string", "format": "date-time" }
      }
    }
  }
}
```

A caller's first call establishes a session (core §1.3's normal
lifecycle — the session scope is *(caller principal, entity)*, so this
naturally reports each caller's own usage, not anyone else's); every
subsequent call is just "what's my usage right now."

**Why this isn't a spec addition.** A protocol-level "quota" concept
would need to define what's being metered (calls? bytes? cost, once
pricing exists?), which is exactly the kind of thing that varies per
provider and shouldn't be standardized prematurely. A `usage` tool with
a provider-defined output shape is the right amount of structure for
v0.1: consistent enough to be discoverable (any caller can look for a
`kind: tool` entity with a name ending in a self-service pattern like
this), flexible enough not to force every provider's metering model into
one schema.

## Using `status` entities (`spec/awp-kinds-v0.1.md` §2)

A `status` entity answers "is this specific thing healthy," not "is the
domain's identity infrastructure up." Fetching `/.well-known/awp.json`
and getting back a validly-signed index already proves the latter — a
`status` entity exists for callers who need the former.

```mermaid
sequenceDiagram
    participant M as monitoring agent
    participant D as some-domain.example

    M->>D: GET /.well-known/awp.json
    D-->>M: signed index (proves identity infra is up)
    M->>D: signed sync call to a kind:status entity
    D-->>M: {"healthy": true, "checked_at": "...", "detail": null}
```

Good candidates for a domain to expose as `kind: status`: a specific
downstream dependency your tools rely on, a queue-depth or
request-latency threshold, anything where "the index responds" would
give a caller false confidence. A domain with nothing more specific to
report than "the daemon is running" doesn't need a `status` entity at
all — that's what the index fetch above already demonstrates.

Conformance/monitoring tooling (a `docs/deployment.md`-style operational
concern) is the most natural consumer: `awp conformance <domain>` could
grow a check that looks for a `kind: status` entity and reports what it
finds, the same way it already reports on the domain index itself.

## Using `received` vs `ack` (`spec/awp-kinds-v0.1.md` §1)

Send `received` when your system has taken custody of an envelope but
hasn't yet decided anything about it — a queue accepted it, nothing more.
Send `ack` (core §2.4) only once something has actually decided to
engage with the message. The distinction matters most for senders
tracking a thread's progress: a `received` with no `ack`/`reply`/`error`
following it within a reasonable window is a legitimate signal that
something is stuck, in a way that's indistinguishable from a healthy
"still working" state if the receiver only ever sends `ack`.

Most receivers don't need this distinction — the reference daemon's
default message handler (`internal/daemon`'s `defaultMessageHandler`,
`docs/agent-guide.md`'s "being called" section) sends `ack` immediately
because it always intends to act. Reach for `received` specifically when
your architecture has a real gap between "accepted" and "a decision was
made" — e.g. a queue-backed system where those two things can be minutes
apart.

## Where to go next

- [`docs/agent-guide.md`](agent-guide.md) — the broader question of what
  an agent's own reasoning loop should do with any of this.
- [`docs/architecture.md`](architecture.md) — how the existing session
  and gate machinery this document leans on actually works.
- `spec/awp-kinds-v0.1.md`, `spec/awp-streaming-v0.1.md` — the two
  normative additions this document assumes.
