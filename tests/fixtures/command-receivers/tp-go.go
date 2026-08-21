package main

import (
	"net/http"
	"os/exec"
)

func handler(r *http.Request) {
	cmd := r.URL.Query().Get("c")
	exec.Command("sh", "-c", cmd)
}
