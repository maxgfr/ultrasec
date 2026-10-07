package main

import "net/http"

func protect(mux *http.ServeMux) http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(mux)
}
