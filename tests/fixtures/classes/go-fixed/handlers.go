package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

func routes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("GET /export/users", func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT id, email FROM users ORDER BY id LIMIT 500")
		defer rows.Close()
		_ = json.NewEncoder(w).Encode(scan(rows))
	})
}
