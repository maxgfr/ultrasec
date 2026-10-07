package demo;

import jakarta.servlet.http.HttpServletRequest;

public class ClientIp {
    String of(HttpServletRequest request) {
        return request.getHeader("X-Forwarded-For").split(",")[0].trim();
    }
}
