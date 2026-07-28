# Security Policy

AWP is a cryptographic protocol (Ed25519 signing, JCS canonicalization,
key rotation, delegation chains) and its reference implementation. A
subtle bug here is usually a security issue, not just a functional one —
please report it privately rather than opening a public issue or PR.

## Scope

Security-relevant issues include (non-exhaustive):

- A way to forge, replay, or otherwise get a signature accepted without
  a valid private key.
- A way to bypass or corrupt key-rotation continuity checks
  (`internal/identity.VerifyRotationChain` and
  `internal/keyresolver`'s continuity enforcement), e.g. accepting an
  unrelated key as a legitimate rotation.
- A way to escape a delegation chain's scope (core §2.5) — acting with
  broader authority than a delegation link actually grants, or getting
  an expired/malformed/discontinuous chain accepted.
- A way to bypass the receiver gate's ordering (core §2.2) in a way that
  has security consequences (e.g. processing an unverified envelope
  before its signature check completes).
- A transport-level downgrade that defeats the HTTPS floor (core §6) —
  e.g. getting an implementation to accept an unauthenticated or
  unencrypted channel where the spec requires TLS.
- Memory-safety or resource-exhaustion issues in `internal/wasmrt`'s
  sandboxing of portable (`wasm32-wasip1`) tool modules.

Issues that are "just" spec ambiguities or missing conformance checks
(not exploitable bugs) belong in a normal public issue — see
`CONTRIBUTING.md`'s spec-vs-implementation split.

## Reporting a vulnerability

**Preferred:** open a
[GitHub Security Advisory](https://github.com/agentask/awp/security/advisories/new)
for this repository — it's private by default and lets us collaborate
on a fix before disclosure.

**Alternative:** email **mevrat@agentask.io** with a description of the
issue, affected package(s)/spec section, and (if possible) a minimal
reproduction.

Please do not open a public GitHub issue for a suspected vulnerability.

## What to expect

This is a small, pre-1.0 open-source project — there's no formal SLA,
but reports will be acknowledged as soon as practical (aim: a few days)
and credited in the fix's commit/release notes unless you'd prefer
otherwise. Given the protocol itself is still `v0.1`/draft (see each
`spec/*.md` document's own "Status" line), expect the fix to sometimes
be a spec clarification, not only a code change.

## Supported versions

Only the `main` branch / latest release receives security fixes — there
is no long-term-support branch at this stage of the project.
