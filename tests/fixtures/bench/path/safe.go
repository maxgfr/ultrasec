package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Cleaned and confined to the base directory; nothing is opened here.
	p := filepath.Clean("/" + name)
	if strings.Contains(p, "..") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
