package main

import (
	"encoding/json"
	"os"
	"time"
)

func main() {
	now := time.Now().UnixNano()
	out := map[string]any{"output": map[string]any{"unix_nano": now}}
	enc, _ := json.Marshal(out)
	os.Stdout.Write(enc)
}
