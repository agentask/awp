package main

import (
	"encoding/json"
	"io"
	"os"
)

type req struct {
	Awp     string          `json:"awp"`
	Caller  string          `json:"caller"`
	Session *string         `json:"session"`
	Input   json.RawMessage `json:"input"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Stderr.WriteString("read error: " + err.Error())
		os.Exit(1)
	}
	var r req
	if err := json.Unmarshal(data, &r); err != nil {
		os.Stderr.WriteString("parse error: " + err.Error())
		os.Exit(1)
	}
	out := map[string]any{"output": map[string]any{"echoed_caller": r.Caller, "input": r.Input}}
	enc, _ := json.Marshal(out)
	os.Stdout.Write(enc)
}
