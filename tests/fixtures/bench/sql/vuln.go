package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func lookup(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM users WHERE id = " + id)
	if err != nil {
		return
	}
	defer rows.Close()
}
