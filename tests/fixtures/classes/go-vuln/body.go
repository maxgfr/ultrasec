package main

import (
	"encoding/json"
	"io"
	"net/http"
)

func importOrders(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var orders []map[string]any
	_ = json.Unmarshal(body, &orders)
	w.WriteHeader(http.StatusNoContent)
}
