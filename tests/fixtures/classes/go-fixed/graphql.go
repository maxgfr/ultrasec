package main

import "net/http"

func mountGraphQL(srv http.Handler) {
	http.Handle("/query", srv)
}
