package main

import (
	"encoding/csv"
	"io"
)

func writeUsers(out io.Writer, users []User) error {
	w := csv.NewWriter(out)
	for _, u := range users {
		if err := w.Write([]string{u.Name, u.Email}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
