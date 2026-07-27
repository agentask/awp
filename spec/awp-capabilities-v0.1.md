# AWP-Capabilities v0.1 — Capability Advertisement, Sandbox Mode, Dry-Run

**Status:** draft. Three small, independent, purely additive extensions
grouped in one document because each is too small to justify its own —
none depends on the others, and none modifies `awp-core-v0.1.md`'s own
text. §1 extends the domain index (core §1.1); §2 and §3 extend the
entity manifest (core §1.2).

## 1. Index `capabilities` (domain-level)

Domain index (core §1.1) gains an OPTIONAL field, in the same spirit as
`awp-quic-v0.1.md` §2's `transports`:

```json
"capabilities": ["awp-streaming-v0.1", "awp-kinds-v0.1/received", "awp-kinds-v0.1/status"]
```

- Each entry is a capability token: either a bare spec short-name
  (`{doc}-v{major}.{minor}`, meaning "this domain implements the whole
  of that document") or a slash-qualified sub-feature
  (`{doc}-v{major}.{minor}/{feature}`, meaning partial adoption — e.g. a
  domain that registers the `received` envelope kind
  (`spec/awp-kinds-v0.1.md` §1) without yet implementing `status`
  entities (§2) advertises `awp-kinds-v0.1/received` only).
- Absence means "no declared optional capabilities" — exactly as absent
  `transports` means HTTPS-only. This field never affects what a domain
  is actually capable of; it only affects whether a caller can discover
  that fact from the index instead of finding out by trying.
- Like `transports`, this lives inside the signed index — attributable
  and downgrade-resistant for the same reason (core §0.1's signature
  covers the whole document minus `sig`).
- Unknown capability tokens MUST be ignored by a reader, exactly as
  `awp-quic-v0.1.md` §2 requires for unknown `proto` values. This field
  is advisory discovery, never something a verifier gates on.

## 2. Manifest `environment` (entity-level)

Entity manifest (core §1.2) gains an OPTIONAL field:

```json
"environment": "sandbox"
```

- Absent, or the literal string `"production"`, means production — the
  default requires no change to any existing manifest.
- `"sandbox"` marks the entity as non-production: safe to integrate
  against without real-world side effects. What "no real side effects"
  means is entity-specific and belongs in `description` (core §1.2's own
  framing: the normative interface surface), not standardized further
  by this field.
- A sandbox entity is signed and verified exactly like any other — this
  field changes what an entity *means*, not how it's authenticated.
- Callers MUST NOT infer anything about a *production* entity's behavior
  from a sandbox entity's responses beyond what the manifest's own
  `description` claims about the relationship between the two — they
  are different entities that happen to share a naming convention, not
  guaranteed-identical implementations.

## 3. Manifest `capabilities` (entity-level) and dry-run

Entity manifest (core §1.2) gains a second OPTIONAL field, distinct in
scope from §1's index-level field — this one describes what one entity
supports, not what a domain supports:

```json
"capabilities": ["dry-run"]
```

Only one token is defined by this document: `dry-run`. A manifest
listing it declares that the entity honors the `AWP-Dry-Run` request
header (below). Absence means the entity does not support dry-run calls
— a caller sending the header to an entity that never declared support
for it MAY have the header silently ignored (this document does not
require an entity to reject a dry-run request it doesn't understand;
`AWP-Dry-Run` is advisory, not part of the signed contract's semantics
the way an unknown `body.type` is for envelopes).

### 3.1 The `AWP-Dry-Run` header

A sync call (`awp-sig-v0.1.md`) MAY carry:

```
AWP-Dry-Run: true
```

- This is an ordinary `AWP-*` header: `internal/httpsig`'s existing
  `CoveredComponents` rule ("every `AWP-*` header present, lowercase,
  alphabetical") already covers it automatically. **No change to the
  signing or verification algorithm is needed** — this is the entire
  reason the header is named with the `AWP-` prefix rather than a bare
  custom header, and is this document's central design point.
- An entity honoring dry-run MUST perform request validation and MUST
  NOT perform any side effect it would otherwise perform for the same
  input. What a "side effect" is remains entity-specific; this document
  does not and cannot enumerate it.
- The response to a dry-run call uses the same shape as a real call
  (`{"output": ...}` or `{"error": ...}`) — a dry run is not a distinct
  wire format, only a distinct execution policy on the receiving side.
- Session behavior (core §1.3) during a dry run is entity-specific and
  unspecified by this document — an entity MAY choose not to issue or
  consume real sessions for dry-run calls, since doing so is itself a
  side effect in some designs and not in others.

## 4. Conformance

1. An index's `capabilities` field, when present, is inside the signed
   document and rejects if tampered (implied by core §0.1 — no new
   check, just confirming this field isn't somehow exempt).
2. A manifest declaring `"capabilities": ["dry-run"]` MUST actually
   avoid side effects on a request carrying `AWP-Dry-Run: true` — this
   is checkable only with cooperation from the entity's own test suite,
   not from outside; a black-box conformance run cannot verify "no side
   effect happened" for an arbitrary tool.
3. A `"environment": "sandbox"` entity is signed/verified with the
   identical procedure as any other entity — no exception, no relaxed
   check.
