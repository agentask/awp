# Contributing to AWP

Thanks for considering a contribution. This is a protocol *and* a
reference implementation of it — read the section below on spec vs.
implementation changes before opening a PR, since the two follow
different review paths.

## Two kinds of change

- **Spec changes** — anything that adds, removes, or changes a rule in
  `spec/*.md`. `spec/` is the source of truth for this project (see
  `CLAUDE.md`): when code and spec disagree, the spec wins and the
  discrepancy gets flagged, not silently resolved in code. Because
  changing the spec affects every implementation (this repo's Go
  reference, `sdk/python`, `sdk/rust`, and anyone else's), **open an
  issue proposing the change before writing a PR** — use the "Spec
  change proposal" issue template. A spec PR without a prior
  issue/discussion will likely be asked to start there first.
- **Implementation-only changes** — bug fixes, performance work, new
  tests, doc fixes, additional conformance checks — that don't touch
  `spec/`. These can go straight to a PR.

If you're not sure which kind your change is, open an issue and ask.

## Building and testing

This is a Go monorepo with two independent SDK reimplementations
(`sdk/python`, `sdk/rust`) that are cross-checked against the Go
implementation's output, not just self-consistent. A PR should pass all
of the following that apply to what you changed:

```sh
# Go: the reference daemon, CLI, and sdk/go
go build ./...
go vet ./...
gofmt -l .          # must print nothing
go test ./... -race

# sdk/python (and agents/python, the same way)
cd sdk/python && uv run pytest

# sdk/rust (and agents/rust, the same way)
cd sdk/rust && cargo test
cargo clippy --all-targets
cargo fmt -- --check
```

**Known exception:** `agents/go`'s `TestInbox_DedupesRepeatedID` has a
genuine, pre-existing data race, diagnosed and recorded in
`docs/experiments.md` (search for "12-feature roadmap: feature #12").
It's tracked separately from this contributing guide's own gate — CI
excludes it from `-race` runs for exactly this reason. If your change
happens to fix it, that's a very welcome, separate PR.

## What a good PR looks like

- Table-driven tests for new validation rules, mirroring the existing
  style in `internal/*_test.go` (per rule, not just per happy path).
- If you add or change a field on a signed document (index, manifest,
  envelope, delegation link), update **all three** of `internal/*`
  (Go), `sdk/python`, and `sdk/rust` — this repo holds itself to a
  cross-language parity bar, not just "the Go daemon does it."
- If the change is externally observable over the wire, consider
  whether `internal/conformance` needs a new checklist item —
  `internal/conformance/streaming.go` or `sync_sig.go` are recent
  examples of the pattern (including how to handle a claim that's
  genuinely unobservable from outside a black-box prober: `Skip` with a
  documented reason, never a fabricated `Pass`).
- Keep commits scoped; don't mix a spec addition with unrelated
  implementation cleanup in the same PR.

## Code style

- Go: standard `gofmt`; no `cgo` anywhere (see `CLAUDE.md`'s fixed
  decisions for why). Comments explain *why*, not just *what* — this
  codebase leans on that pattern heavily; match it.
- Errors: one grammar everywhere, `{code, detail, retryable}` (core
  §2.6) — sync and async paths share the same handler shape.
- Rust: `cargo fmt`, and `cargo clippy` clean.
- Python: match the existing style in `sdk/python`/`agents/python`
  (dataclasses, `from __future__ import annotations`, type hints
  throughout).

## Where to go next

- `CLAUDE.md` — the detailed build plan, fixed architectural decisions,
  and phase history this project was actually built against.
- `docs/architecture.md` — how the `internal/*` packages fit together.
- `docs/protocol-overview.md` — the concepts, in plain English.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability
  privately, rather than in a public issue.
