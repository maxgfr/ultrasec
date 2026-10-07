package main

import (
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	return strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
}
