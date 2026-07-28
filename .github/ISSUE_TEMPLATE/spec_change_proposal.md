---
name: Spec change proposal
about: Propose adding, changing, or removing a rule in spec/*.md
title: ""
labels: spec
assignees: ""
---

Changing the spec affects every implementation of AWP, not just this
repo's own reference daemon — that's why spec changes start as a
proposal here, before a PR. See `CONTRIBUTING.md`'s "Two kinds of
change" for the full reasoning.

**Which document / section?**
e.g. `spec/awp-core-v0.1.md` §2.4, or "a new `spec/awp-<name>-v0.1.md`".

**What's the problem this solves?**
What can't be expressed, or is ambiguous, in the current spec? Concrete
use case appreciated over abstract motivation.

**Proposed change**
Sketch the actual wire-format/behavior change, even roughly. If you have
a preference between a few approaches, name the tradeoffs — the
"Rejected: ..." / "Adopted: ..." framing used in e.g.
`spec/awp-transactions-v0.1.md` §0 or `spec/awp-streaming-v0.1.md` §8 is
a good model to follow.

**Is this purely additive, or does it change existing behavior?**
Purely additive (a new optional field, a new registered `kind`, a new
extension document) is a much lighter review than anything that changes
what an existing, already-implemented rule means.

**Backward compatibility**
What happens to an implementation that hasn't adopted this change yet,
when it encounters the new behavior on the wire? (Most extensions in
this repo answer this explicitly — see any `spec/awp-*-v0.1.md`
document's own backward-compatibility section for the pattern.)
