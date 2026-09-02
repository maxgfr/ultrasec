package main

import (
	"crypto/aes"
	"net/http"
)

func encrypt(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	// AES, not DES: a modern primitive.
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return
	}
	_ = block
}
