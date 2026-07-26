// Command tool is a portable AWP entity: a wasm32-wasip1 binary speaking
// the stdio-json/1 interface (core §1.2) directly, with no AWP-aware
// runtime linked in — it just reads one JSON request from stdin and
// writes one JSON response to stdout. This same binary could run under
// any stdio-json/1 host, not only internal/wasmrt.
package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"
)

type request struct {
	Awp     string          `json:"awp"`
	Caller  string          `json:"caller"`
	Session *string         `json:"session"`
	Input   json.RawMessage `json:"input"`
}

type wordCountInput struct {
	Text string `json:"text"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Stderr.WriteString("read stdin: " + err.Error())
		os.Exit(1)
	}
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		os.Stderr.WriteString("parse request: " + err.Error())
		os.Exit(1)
	}
	var in wordCountInput
	if err := json.Unmarshal(req.Input, &in); err != nil {
		writeJSON(map[string]any{
			"error": map[string]any{"code": "unsupported_body", "detail": `want {"text":string}`, "retryable": false},
		})
		return
	}

	words := 0
	if strings.TrimSpace(in.Text) != "" {
		words = len(strings.Fields(in.Text))
	}
	// time.Now() deliberately surfaces internal/wasmrt's clock capability
	// gating: without Config.Capabilities including "clock", wazero's
	// WASI clock is a deterministic fake and this is always the same
	// value; with it granted, it's the real wall clock.
	writeJSON(map[string]any{
		"output": map[string]any{
			"caller":      req.Caller,
			"word_count":  words,
			"char_count":  len(in.Text),
			"observed_at": time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func writeJSON(v any) {
	enc, err := json.Marshal(v)
	if err != nil {
		os.Stderr.WriteString("marshal response: " + err.Error())
		os.Exit(1)
	}
	os.Stdout.Write(enc)
}
