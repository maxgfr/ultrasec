package main

import (
	"net/http"
	"strings"
)

// One trusted proxy: the client is the last hop, the one it appended.
func clientIP(r *http.Request) string {
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	return strings.TrimSpace(hops[len(hops)-1])
}
