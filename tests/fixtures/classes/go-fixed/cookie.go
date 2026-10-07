package main

import "net/http"

func remember(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}
