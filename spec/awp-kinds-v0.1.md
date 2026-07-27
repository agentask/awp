# AWP-Kinds v0.1 — Additional Envelope and Entity Kinds

**Status:** draft. Purely additive registrations against
`awp-core-v0.1.md` §1.2/§1.4 (entity `kind`) and §2.4 (envelope `kind`).
This document does not modify, supersede, or reopen any text in
`awp-core-v0.1.md` — it only adds new values to two vocabularies that
core itself treats as extensible.

Two unrelated additions live in one document because both are small
enough that a dedicated document each would be noise; §1 and §2 have no
dependency on each other and may be adopted independently.

## Why this is additive, not a core edit

Envelope `kind` is never enforced by the receiver gate (core §2.2) — the
gate's five checks (parse, TTL, signature, dedupe, enqueue) never inspect
`kind` at all; dispatch on `kind` happens entirely at the application
layer, after the gate has already accepted an envelope. Registering a
new `kind` value therefore changes no verified wire behavior for anyone
who hasn't implemented it: an implementation that doesn't recognize
`received` (§1) simply never sends or expects one, exactly as it
wouldn't today. The same is true of entity `kind` (§2) with respect to
manifest/index parsing — `entities[].kind` is a plain string, and a new
value doesn't require any implementation to change how it parses an
index it already resolves correctly.

## 1. Envelope kind: `received`

Registered alongside core §2.4's existing table
(`message`/`reply`/`error`/`ack`/`close`):

| Kind | Meaning |
|---|---|
| `received` | Passive transport-level receipt: the entity's own application layer took custody of the envelope, with no claim about whether or when it will be acted on. |

This is deliberately weaker than `ack` (core §2.4: "Optional application
receipt (seen, working)"). `ack` implies engagement — the receiver has
decided to process the envelope and is telling the sender so. `received`
implies nothing beyond "this envelope now exists somewhere on my side" —
appropriate for automated, no-decision-made-yet receipts, or for a
receiving system that wants to distinguish "I have it" from "I'm working
on it" without conflating the two the way a single `ack` kind would.

`received` MUST NOT be treated by a sender as evidence that the receiver
will ever reply, ack, or close the thread — it carries strictly less
information than `ack`, not an alternative form of the same information.
Senders MAY send `received` automatically upon successful gate
acceptance, prior to any application-level decision about the message.

## 2. Entity kind: `status`

Registered alongside core §1.4's interaction semantics
(`tool`/`app`/`agent`):

> `status` → one sync request/response against `hosted.endpoint` only —
> `distribution.portable` MUST NOT be the sole distribution for a
> `status` entity, since a locally-run module cannot attest to the
> *remote* domain's health. `state` MUST be `stateless` (core §1.3): a
> health check that depends on session state isn't answering the
> question a caller is asking.

### 2.1 Purpose

A machine-checkable "is this domain currently healthy" endpoint, as
distinct from "does its index respond." A domain's `/.well-known/awp.json`
being fetchable and correctly signed proves the domain's *identity*
infrastructure is up; it says nothing about whether any particular
entity behind it is actually functioning. A `status` entity exists to
answer that second, narrower question for whichever specific concern its
manifest's `description` says it monitors (a database connection, a
downstream dependency, request-queue depth — the manifest's
`description` field, per core §1.2, is the "normative interface surface"
that says which).

### 2.2 Response shape

A `status` entity's `io.output` MUST be a superset of:

```json
{
  "healthy": true,
  "checked_at": "2026-07-27T09:00:00.000Z",
  "detail": "optional human-readable elaboration, or null"
}
```

| Field | Rules |
|---|---|
| `healthy` | Boolean. The entity's own assessment at the moment of the call — not cached across calls beyond what `checked_at` honestly reflects. |
| `checked_at` | RFC 3339 UTC, millisecond precision (core §0), the instant the check was actually performed. |
| `detail` | OPTIONAL. Free text or a structured sub-object; this document does not standardize its shape beyond "present or `null`." |

A `status` entity MAY include additional fields beyond these three; a
caller MUST NOT fail to parse a conforming response solely because it
contains fields this document didn't anticipate.

### 2.3 Auth

`auth.sig` remains `"required"` (core §1.2 — always true in v0.1); a
`status` entity's response is signed exactly like any other sync tool
response, including the awp-sig §3 SHOULD for response signing. A status
check is not exempt from authentication just because it's read-only.

## 3. Conformance

1. A `received` envelope is never sent as a substitute for `ack` where
   the sending entity has actually decided to process the message — the
   two are not interchangeable in either direction.
2. A `status` entity always responds `stateless` and via
   `distribution.hosted`; a portable-only manifest claiming `kind: status`
   is non-conforming.
3. A `status` entity's `checked_at` reflects the actual check instant,
   not a cached or startup-time value, for every call.
