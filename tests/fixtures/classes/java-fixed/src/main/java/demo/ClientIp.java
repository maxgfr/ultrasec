package demo;

import jakarta.servlet.http.HttpServletRequest;

public class ClientIp {
    // One trusted proxy: the last hop is the one it wrote.
    String of(HttpServletRequest request) {
        String[] hops = request.getHeader("X-Forwarded-For").split(",");
        return hops[hops.length - 1].trim();
    }
}
