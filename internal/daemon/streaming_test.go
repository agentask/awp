package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentask/awp/internal/apperr"
	"github.com/agentask/awp/internal/clock"
	"github.com/agentask/awp/internal/envelope"
	"github.com/agentask/awp/internal/store"
)

func streamChunkBodyJSON(t *testing.T, streamID string, seq int, final bool, text string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type": "stream_chunk", "stream_id": streamID, "seq": seq, "final": final,
		"data": map[string]string{"text": text},
	})
	if err != nil {
		t.Fatalf("marshal stream_chunk body: %v", err)
	}
	return raw
}

type recordedChunk struct {
	thread, streamID string
	seq              int
	final            bool
	data             json.RawMessage
}

func newStreamingTestDaemon(t *testing.T, domain string, clk clock.Clock, cfgOverrides func(*Config)) *Daemon {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), domain+".db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{Domain: domain, Kid: "k1", Priv: priv, Store: st, Clock: clk, Resolver: noopResolver{}}
	if cfgOverrides != nil {
		cfgOverrides(&cfg)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// TestProcessInboundOnce_StreamChunk_InOrderDeliveredToHandler covers
// awp-streaming-v0.1.md §4: chunks arriving in order are delivered to
// StreamChunkHandler one at a time, and the stream_chunk body bypasses
// the normal message/ack/reply dispatch entirely (no auto-response).
func TestProcessInboundOnce_StreamChunk_InOrderDeliveredToHandler(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	var got []recordedChunk
	d := newStreamingTestDaemon(t, "b.example.com", clock.NewFixed(now), func(cfg *Config) {
		cfg.StreamChunkHandler = func(_ context.Context, thread, streamID string, seq int, final bool, data json.RawMessage) error {
			got = append(got, recordedChunk{thread, streamID, seq, final, data})
			return nil
		}
	})

	thread := envelope.NewID()
	streamID := envelope.NewID()
	for seq, text := range []string{"a", "b", "c"} {
		final := seq == 2
		injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, streamID, seq, final, text), now)
	}

	n, err := d.ProcessInboundOnce(context.Background())
	if err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 processed, got %d", n)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 chunks delivered to the handler, got %d: %+v", len(got), got)
	}
	for seq, c := range got {
		if c.seq != seq || c.thread != thread || c.streamID != streamID {
			t.Fatalf("chunk %d: got %+v", seq, c)
		}
	}
	if !got[2].final {
		t.Fatal("expected the last delivered chunk to have final=true")
	}

	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("expected no auto-response (ack/reply/error) to stream_chunk envelopes, got %d", len(due))
	}
}

// TestProcessInboundOnce_StreamChunk_OutOfOrderStillDeliveredInOrder
// injects chunks out of arrival order and confirms the handler still
// only ever sees them in seq order, with no gap.
func TestProcessInboundOnce_StreamChunk_OutOfOrderStillDeliveredInOrder(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	var gotSeqs []int
	d := newStreamingTestDaemon(t, "b.example.com", clock.NewFixed(now), func(cfg *Config) {
		cfg.StreamChunkHandler = func(_ context.Context, _, _ string, seq int, _ bool, _ json.RawMessage) error {
			gotSeqs = append(gotSeqs, seq)
			return nil
		}
	})

	thread := envelope.NewID()
	streamID := envelope.NewID()
	// Arrival order: 2, 0, 1 — seq 2 must not be delivered until 0 and 1
	// have both arrived.
	injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, streamID, 2, true, "c"), now)
	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce (seq 2): %v", err)
	}
	if len(gotSeqs) != 0 {
		t.Fatalf("expected no delivery yet (0,1 missing), got %v", gotSeqs)
	}

	injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, streamID, 0, false, "a"), now)
	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce (seq 0): %v", err)
	}
	if len(gotSeqs) != 1 || gotSeqs[0] != 0 {
		t.Fatalf("expected only seq 0 delivered, got %v", gotSeqs)
	}

	injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, streamID, 1, false, "b"), now)
	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce (seq 1): %v", err)
	}
	if len(gotSeqs) != 3 || gotSeqs[1] != 1 || gotSeqs[2] != 2 {
		t.Fatalf("expected cascading delivery of [0,1,2], got %v", gotSeqs)
	}
}

// TestProcessInboundOnce_StreamChunk_MalformedBody_SendsRefused covers a
// stream_chunk body missing required fields — no handler invocation, an
// error(refused) envelope back to the sender.
func TestProcessInboundOnce_StreamChunk_MalformedBody_SendsRefused(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	handlerCalled := false
	d := newStreamingTestDaemon(t, "b.example.com", clock.NewFixed(now), func(cfg *Config) {
		cfg.StreamChunkHandler = func(context.Context, string, string, int, bool, json.RawMessage) error {
			handlerCalled = true
			return nil
		}
	})

	thread := envelope.NewID()
	badBody := json.RawMessage(`{"type":"stream_chunk","final":false}`) // no stream_id, no seq
	injectInbound(t, d, "a.example.com", "reply", thread, nil, badBody, now)

	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if handlerCalled {
		t.Fatal("expected the handler NOT to be invoked for a malformed stream_chunk body")
	}

	errEnv := requireSingleErrorEnvelope(t, d, now)
	assertErrorBody(t, errEnv, apperr.CodeRefused)
}

// TestProcessInboundOnce_StreamChunk_DisabledStreaming_SendsUnsupportedBody
// covers core §2.3/awp-streaming-v0.1.md §9: an implementation that has
// not adopted streaming rejects stream_chunk with error(unsupported_body).
func TestProcessInboundOnce_StreamChunk_DisabledStreaming_SendsUnsupportedBody(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	handlerCalled := false
	d := newStreamingTestDaemon(t, "b.example.com", clock.NewFixed(now), func(cfg *Config) {
		cfg.DisableStreaming = true
		cfg.StreamChunkHandler = func(context.Context, string, string, int, bool, json.RawMessage) error {
			handlerCalled = true
			return nil
		}
	})

	thread := envelope.NewID()
	injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, envelope.NewID(), 0, true, "x"), now)

	if _, err := d.ProcessInboundOnce(context.Background()); err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if handlerCalled {
		t.Fatal("expected the handler NOT to be invoked when streaming is disabled")
	}

	errEnv := requireSingleErrorEnvelope(t, d, now)
	assertErrorBody(t, errEnv, apperr.CodeUnsupportedBody)
}

// TestProcessInboundOnce_StreamChunk_NoHandlerConfigured confirms a nil
// StreamChunkHandler (the default) doesn't crash or error — chunks are
// still correctly reassembled internally, just not pushed anywhere.
func TestProcessInboundOnce_StreamChunk_NoHandlerConfigured(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newStreamingTestDaemon(t, "b.example.com", clock.NewFixed(now), nil)

	thread := envelope.NewID()
	injectInbound(t, d, "a.example.com", "reply", thread, nil, streamChunkBodyJSON(t, envelope.NewID(), 0, true, "x"), now)

	n, err := d.ProcessInboundOnce(context.Background())
	if err != nil {
		t.Fatalf("ProcessInboundOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 processed, got %d", n)
	}
	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("expected no auto-response, got %d", len(due))
	}
}

// TestNew_AdvertisesStreamingCapabilityByDefault and its sibling below
// cover awp-capabilities-v0.1.md §1's advertisement of adoption.
func TestNew_AdvertisesStreamingCapabilityByDefault(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newStreamingTestDaemon(t, "a.example.com", clock.NewFixed(now), nil)
	raw, err := json.Marshal(d.index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	var idx struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	found := false
	for _, c := range idx.Capabilities {
		if c == "awp-streaming-v0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \"awp-streaming-v0.1\" advertised by default, got %v", idx.Capabilities)
	}
}

func TestNew_DisableStreamingOmitsCapability(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	d := newStreamingTestDaemon(t, "a.example.com", clock.NewFixed(now), func(cfg *Config) {
		cfg.DisableStreaming = true
	})
	raw, err := json.Marshal(d.index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	var idx struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}
	for _, c := range idx.Capabilities {
		if c == "awp-streaming-v0.1" {
			t.Fatalf("expected no streaming capability advertised when disabled, got %v", idx.Capabilities)
		}
	}
}

// requireSingleErrorEnvelope drains the outbox and asserts exactly one
// `error` envelope was enqueued in response to the triggering chunk.
func requireSingleErrorEnvelope(t *testing.T, d *Daemon, now time.Time) envelope.Envelope {
	t.Helper()
	due, err := d.Store.DueForDelivery(now, 10)
	if err != nil {
		t.Fatalf("DueForDelivery: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("expected exactly 1 outbound envelope (the error), got %d", len(due))
	}
	var e envelope.Envelope
	if err := json.Unmarshal(due[0].Envelope, &e); err != nil {
		t.Fatalf("unmarshal error envelope: %v", err)
	}
	if e.Kind != "error" {
		t.Fatalf("expected kind=error, got %q", e.Kind)
	}
	return e
}

func assertErrorBody(t *testing.T, e envelope.Envelope, wantCode string) {
	t.Helper()
	var body struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	if err := json.Unmarshal(e.Body, &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if body.Data.Code != wantCode {
		t.Fatalf("error code = %q, want %q", body.Data.Code, wantCode)
	}
}
