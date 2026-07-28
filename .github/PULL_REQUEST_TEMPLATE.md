## What does this PR do?

<!-- One or two sentences. Link the issue this resolves, if any. -->

## Does this touch `spec/`?

- [ ] No — implementation only (bug fix, tests, docs, conformance check).
- [ ] Yes — linked issue/discussion: <!-- required for spec changes, see CONTRIBUTING.md -->

## Checklist

- [ ] `go build ./... && go vet ./... && gofmt -l .` clean
- [ ] `go test ./... -race` green (aside from the known, tracked
      `agents/go` race — see `CONTRIBUTING.md`)
- [ ] If this changes a signed-document field (index/manifest/envelope/
      delegation link): `sdk/python` and `sdk/rust` updated too, not
      just `internal/*`/`sdk/go`
- [ ] If this is externally observable over the wire: considered whether
      `internal/conformance` needs a new checklist item
- [ ] `sdk/python`: `uv run pytest` green (if touched)
- [ ] `sdk/rust`: `cargo test && cargo clippy --all-targets && cargo fmt -- --check` green (if touched)

## Anything reviewers should look at closely?

<!-- Optional: tricky edge cases, alternatives you considered and rejected, etc. -->
