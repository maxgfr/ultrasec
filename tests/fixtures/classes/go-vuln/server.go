package main

import "net/http"

func serve(mux *http.ServeMux) error {
	return http.ListenAndServe(":8080", mux)
}
