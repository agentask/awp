---
name: Bug report
about: Something in the reference implementation doesn't match the spec, or crashes/misbehaves
title: ""
labels: bug
assignees: ""
---

**Which implementation?**
`internal/*` (the Go reference daemon), `sdk/go`, `sdk/python`, `sdk/rust`,
`agents/*`, or the conformance CLI (`awp conformance`)?

**What happened**
A clear description of the observed behavior.

**What you expected**
What the spec (`spec/*.md` — name the document/section if you know it)
says should happen instead. If you're not sure whether this is a spec
ambiguity or an implementation bug, that's fine — say so and we'll sort
it out.

**How to reproduce**
Minimal steps, ideally a command or short code snippet. Include the
exact gate command output if relevant (`go test ./... -race`, `cargo
test`, `uv run pytest`, etc.).

**Environment**
- OS / Go version / Python version / Rust version (whichever apply)
- Commit or tag

**Is this possibly a security issue?**
If this looks like it could let something bypass a signature check,
delegation scope, or key-rotation continuity — please don't file it
here. See [`SECURITY.md`](../../SECURITY.md) instead.
