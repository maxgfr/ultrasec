package main

import (
	"crypto/subtle"
	"net/http"
	"os"
)

func requireKey(w http.ResponseWriter, r *http.Request) bool {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Api-Key")), []byte(os.Getenv("API_KEY"))) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}
