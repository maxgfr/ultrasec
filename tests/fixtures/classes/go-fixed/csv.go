package main

import (
	"encoding/csv"
	"io"
	"strings"
)

func cell(v string) string {
	for _, p := range []string{"=", "+", "-", "@", "\t", "\r"} {
		if strings.HasPrefix(v, p) {
			return "'" + v
		}
	}
	return v
}

func writeUsers(out io.Writer, users []User) error {
	w := csv.NewWriter(out)
	for _, u := range users {
		if err := w.Write([]string{cell(u.Name), cell(u.Email)}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
