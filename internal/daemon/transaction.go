package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// Transaction is the decoded shape of an AWP-Transaction header
// (awp-transactions-v0.1.md §2): base64url(JSON({id, step, coordinator})).
type Transaction struct {
	ID          string `json:"id"`
	Step        int    `json:"step"`
	Coordinator string `json:"coordinator"`
}

// transactionKey is an unexported context key type — same idiom as
// dryRunKey: only WithTransaction/TransactionFromContext below can set or
// read it.
type transactionKey struct{}

// WithTransaction records the decoded AWP-Transaction header, if any, on
// ctx. serveToolCall sets this before invoking a ToolHandler; a handler
// that wants (id, step) for compensation dedupe (awp-transactions-v0.1.md
// §2.1) reads it via TransactionFromContext rather than the ToolHandler
// signature itself changing — the same non-breaking pattern WithDryRun
// established.
func WithTransaction(ctx context.Context, txn *Transaction) context.Context {
	return context.WithValue(ctx, transactionKey{}, txn)
}

// TransactionFromContext returns the decoded AWP-Transaction header, and
// whether one was present at all. A context that was never touched by
// WithTransaction, or whose call carried no header, reports ok=false.
func TransactionFromContext(ctx context.Context) (txn *Transaction, ok bool) {
	txn, ok = ctx.Value(transactionKey{}).(*Transaction)
	return txn, ok && txn != nil
}

// ErrMalformedTransactionHeader means an AWP-Transaction header was
// present but failed to decode — awp-transactions-v0.1.md §2: unlike
// AWP-Dry-Run's single boolean, this header has an invalid non-empty
// state, and a caller sending it at all is claiming a shape it must
// actually honor.
var ErrMalformedTransactionHeader = errors.New("daemon: malformed AWP-Transaction header")

// parseTransactionHeader decodes an AWP-Transaction header value. An
// empty header (not present at all) returns (nil, nil) — no transaction,
// not an error.
func parseTransactionHeader(header string) (*Transaction, error) {
	if header == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, ErrMalformedTransactionHeader
	}
	var txn Transaction
	if err := json.Unmarshal(raw, &txn); err != nil {
		return nil, ErrMalformedTransactionHeader
	}
	if txn.ID == "" {
		return nil, ErrMalformedTransactionHeader
	}
	return &txn, nil
}
