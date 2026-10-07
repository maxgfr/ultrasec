package main

import (
	"net/http"
	"os"
)

func requireKey(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Api-Key") != os.Getenv("API_KEY") {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}
