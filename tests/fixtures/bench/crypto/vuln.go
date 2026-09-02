package main

import (
	"crypto/des"
	"net/http"
)

func encrypt(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return
	}
	_ = block
}
