package main

import (
	"encoding/json"
	"io"
	"os"
)

func main() {
	_, _ = io.ReadAll(os.Stdin)
	os.Stderr.WriteString("SENSITIVE_HOST_LOG_MARKER_12345")
	out := map[string]any{"output": map[string]any{"ok": true}}
	enc, _ := json.Marshal(out)
	os.Stdout.Write(enc)
}
