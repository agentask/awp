package main

import "crypto/sha256"

func main() {
	data := make([]byte, 64)
	for range 2_000_000 {
		sum := sha256.Sum256(data)
		data = sum[:]
	}
}
