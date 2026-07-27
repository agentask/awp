package daemon

import "context"

// dryRunKey is an unexported context key type — the standard Go idiom
// for context values that shouldn't collide with anything else, and
// deliberately not exported itself: only WithDryRun/IsDryRun below can
// set or read it.
type dryRunKey struct{}

// WithDryRun records whether the current sync tool call carried
// AWP-Dry-Run: true (awp-capabilities-v0.1.md §3). serveToolCall sets
// this before invoking a ToolHandler; a handler that wants to honor
// dry-run reads it via IsDryRun rather than the ToolHandler signature
// itself changing — avoiding a breaking change to every existing
// Tool.Handler for a capability most tools will never need to check.
func WithDryRun(ctx context.Context, dryRun bool) context.Context {
	return context.WithValue(ctx, dryRunKey{}, dryRun)
}

// IsDryRun reports whether ctx was produced by WithDryRun(ctx, true).
// A context that was never touched by WithDryRun reports false —
// matching AWP-Dry-Run's own absence-means-not-a-dry-run default
// (awp-capabilities-v0.1.md §3.1).
func IsDryRun(ctx context.Context) bool {
	v, _ := ctx.Value(dryRunKey{}).(bool)
	return v
}
