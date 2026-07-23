// Package apperr defines the single {code, detail, retryable} error grammar
// shared by sync and async paths (core §2.6).
package apperr

import "fmt"

// Error is the wire shape of every AWP error, sync or async:
// {"error": {"code", "detail", "retryable"}}.
type Error struct {
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	Retryable bool   `json:"retryable"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

// Body wraps Error in the top-level {"error": ...} envelope used on the
// wire (core §2.6).
type Body struct {
	Error *Error `json:"error"`
}

// Registered core §2.4 error codes.
const (
	CodeUnsupportedBody        = "unsupported_body"
	CodeUnauthorizedDelegation = "unauthorized_delegation"
	CodeCapacity               = "capacity"
	CodeRefused                = "refused"
	CodeInternal               = "internal"
)

// Unregistered but non-colliding codes used by the core §2.2 receiver gate,
// which rejects before any application-level error envelope would apply.
const (
	CodeMalformed    = "malformed"
	CodeExpired      = "expired"
	CodeUnauthorized = "unauthorized"
)
