# AWP-Versioning v0.1 — Manifest Changelog Pointer and Version Chaining

**Status:** draft. One small, purely additive extension to the entity
manifest (core §1.2). Resolves the open question left in the roadmap: does
AWP need an archival mechanism for previous manifest content? **No** — this
document is deliberately narrow about what it does *not* promise.

## 0. What this document does not do

Core §1.1's index pins exactly one `manifest_sha256` per entity: the
**current** version. Nothing in core AWP requires a previous manifest's
raw bytes to remain fetchable anywhere, at any URL, ever, once a domain
publishes a new version. This document does not change that. It adds two
purely optional fields that let a domain *choose* to make its version
history legible, without obligating anyone to retain anything.

## 1. Manifest `changelog` (informational pointer)

Entity manifest (core §1.2) gains an OPTIONAL field:

```json
"changelog": "https://example.com/awp/changelogs/generate-invoice.html"
```

- A URL, meant for a human or an agent summarizing "what changed." Like
  `pricing` and `inbox`, this is informational metadata inside the signed
  document — its presence and value are attributable (tampering with the
  URL invalidates `sig` like any other field), but AWP makes **no
  retrieval or content guarantee** about what that URL currently serves.
  A `404` there is a documentation gap, not a protocol violation.
- Absent means no changelog is published. This never gates anything —
  no conformance check may require a working `changelog` URL.

## 2. Manifest `previous_sha256` (optional hash-chain link)

Entity manifest (core §1.2) gains a second OPTIONAL field:

```json
"previous_sha256": "hex"
```

- The sha256 (hex, same form as `entities[].manifest_sha256`) of the
  immediately-prior signed manifest document's raw bytes — the version
  this one supersedes.
- This is a **self-asserted continuity marker**, not a fetchable archive
  entry. It only pays off for whoever happens to hold the prior document
  (a caller that cached it from an earlier index fetch, or a third-party
  archiver): they can confirm "this new manifest legitimately claims to
  supersede that exact prior one," the same way a rotation chain's
  `prev_sig` (core §1.1 rule 2) lets a holder of the old key confirm
  continuity without any registry storing every historical key.
- A verifier with no cached prior document simply cannot check this field
  — that is expected, not an error. `previous_sha256` is unverifiable in
  isolation, exactly like a rotation chain's very first trust anchor.
- The first manifest an entity ever publishes omits this field (there is
  no prior version). A domain that loses its own record of the prior
  manifest's hash (e.g. after an operator-side incident) MAY also omit
  it on the next version — this breaks the chain, visibly, rather than
  faking continuity; that is preferable to a false link.
- `previous_sha256` MUST refer to a manifest signed by the same
  `domainOf(name)`, but this document does not require verifiers to
  check that — only holders of the actual prior bytes can, and doing so
  is their own diligence, not a wire-level obligation.

## 3. Version discipline

Core §1.2 already states: "Breaking I/O changes MUST bump major." This
document adds: whenever `previous_sha256` changes from one published
manifest to the next (i.e., whenever the signed content actually
changed), `version` SHOULD also change — `previous_sha256` chaining two
manifests that both claim the same `version` string is a signal something
was republished without a version bump, which conformance MAY flag as a
warning (not a hard failure — `version` discipline is the publisher's
responsibility, not something a receiver can fully enforce from outside).

## 4. Conformance

1. `changelog` and `previous_sha256`, when present, are inside the signed
   document and reject verification if tampered — implied by core §0.1,
   not a new check.
2. No conformance check may dereference `changelog` and fail on a bad
   response — it is informational only (§1).
3. A conformance run MAY warn (never hard-fail) if it observes two
   manifest versions for the same entity where `previous_sha256` links
   them but `version` is unchanged (§3).
