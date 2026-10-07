package demo;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

public class SessionCookie {
    ResponseEntity<Void> issue(String token) {
        ResponseCookie cookie = ResponseCookie.from("sid", token)
            .httpOnly(true)
            .secure(true)
            .sameSite("Lax")
            .path("/")
            .build();
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
    }
}
