package com.example.crypto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Mints a password-reset token from a predictable RNG. */
public class WeakToken {

    public void reset(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String email = request.getParameter("email");

        java.util.Random rng = new java.util.Random();
        String token = Integer.toString(rng.nextInt(1000000));

        response.getWriter().println("reset link for " + email + " token " + token);
    }
}
