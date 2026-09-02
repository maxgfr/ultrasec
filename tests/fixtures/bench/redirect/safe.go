package main

import "net/http"

func login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	_ = next
	// Fixed destination: the parameter is ignored.
	w.Header().Set("Location", "/home")
	w.WriteHeader(http.StatusFound)
}
