package main

import (
	"net/http"

	"github.com/99designs/gqlgen/graphql/playground"
)

func mountGraphQL(srv http.Handler) {
	http.Handle("/", playground.Handler("GraphQL", "/query"))
	http.Handle("/query", srv)
}
