package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
)

func main() {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	out := map[string]any{"output": map[string]any{"random_hex": hex.EncodeToString(b)}}
	enc, _ := json.Marshal(out)
	os.Stdout.Write(enc)
}
