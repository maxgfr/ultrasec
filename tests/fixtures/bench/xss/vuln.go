package main

import (
	"fmt"
	"net/http"
)

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "<h1>Results for %s</h1>", q)
}
