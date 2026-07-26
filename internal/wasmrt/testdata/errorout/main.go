package main

import (
	"encoding/json"
	"io"
	"os"
)

func main() {
	_, _ = io.ReadAll(os.Stdin)
	out := map[string]any{"error": map[string]any{"code": "refused", "detail": "nope", "retryable": false}}
	enc, _ := json.Marshal(out)
	os.Stdout.Write(enc)
}
