"""pyawp: a minimal Python implementation of the AWP wire protocol
(spec/awp-core-v0.1.md), precise enough to interoperate with this
repo's Go reference implementation — see scripts/crosscheck_go.py.

Scope, deliberately: this is not a general-purpose SDK. It implements
exactly what agents/python's two demo agents need — signed domain
indexes, signed async envelopes, a minimal inbox gate, and nothing else
(no delegation, no sync tool calls, no persistence). See its README for
what's real versus simplified relative to the Go implementation.
"""
