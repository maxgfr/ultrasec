package main

import (
	"net/http"
	"os"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, err := os.ReadFile("/srv/files/" + name)
	if err != nil {
		return
	}
	_ = data
}
