package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("search").Parse("<h1>Results for {{.}}</h1>"))

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// html/template escapes contextually; the value is data, not markup.
	page.Execute(w, q)
}
