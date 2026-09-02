package main

import (
	"net/http"
	"strconv"
)

func lookup(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// Coerced to an integer and never concatenated into a statement.
	n, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = n
	w.WriteHeader(http.StatusOK)
}
