package daemon

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestParseTransactionHeader_Empty_ReturnsNilNoError(t *testing.T) {
	txn, err := parseTransactionHeader("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if txn != nil {
		t.Fatalf("expected nil transaction for an empty header, got %+v", txn)
	}
}

func TestParseTransactionHeader_ValidRoundTrips(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"id":"01hxxx","step":3,"coordinator":"caller.example.com"}`))
	txn, err := parseTransactionHeader(header)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if txn.ID != "01hxxx" || txn.Step != 3 || txn.Coordinator != "caller.example.com" {
		t.Fatalf("got %+v", txn)
	}
}

func TestParseTransactionHeader_MalformedTableDriven(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"not base64url", "!!!not-base64url!!!"},
		{"base64url but not JSON", base64.RawURLEncoding.EncodeToString([]byte("plain text"))},
		{"JSON but missing id", base64.RawURLEncoding.EncodeToString([]byte(`{"step":1}`))},
		{"JSON but empty id", base64.RawURLEncoding.EncodeToString([]byte(`{"id":"","step":1}`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseTransactionHeader(tt.header); err != ErrMalformedTransactionHeader {
				t.Fatalf("got err=%v, want ErrMalformedTransactionHeader", err)
			}
		})
	}
}

func TestTransactionFromContext_AbsentByDefault(t *testing.T) {
	if txn, ok := TransactionFromContext(context.Background()); ok || txn != nil {
		t.Fatalf("expected ok=false, txn=nil on an untouched context, got ok=%v txn=%+v", ok, txn)
	}
}

func TestTransactionFromContext_NilTransactionMeansAbsent(t *testing.T) {
	ctx := WithTransaction(context.Background(), nil)
	if txn, ok := TransactionFromContext(ctx); ok || txn != nil {
		t.Fatalf("expected ok=false, txn=nil when WithTransaction(ctx, nil) was used, got ok=%v txn=%+v", ok, txn)
	}
}

func TestTransactionFromContext_RoundTrips(t *testing.T) {
	want := &Transaction{ID: "01hxxx", Step: 1, Coordinator: "caller.example.com"}
	ctx := WithTransaction(context.Background(), want)
	got, ok := TransactionFromContext(ctx)
	if !ok || *got != *want {
		t.Fatalf("got ok=%v txn=%+v, want ok=true txn=%+v", ok, got, want)
	}
}
