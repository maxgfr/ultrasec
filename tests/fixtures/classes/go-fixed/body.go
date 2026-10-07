package main

import (
	"encoding/json"
	"io"
	"net/http"
)

func importOrders(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	var orders []map[string]any
	_ = json.Unmarshal(body, &orders)
	w.WriteHeader(http.StatusNoContent)
}
