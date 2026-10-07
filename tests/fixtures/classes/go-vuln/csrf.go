package main

import "net/http"

func protect(mux *http.ServeMux) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern("POST /transfer")
	return cop.Handler(mux)
}
