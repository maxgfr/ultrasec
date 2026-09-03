package com.example.crypto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** The same shape, drawing from a CSPRNG. */
public class StrongToken {

    public void reset(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String email = request.getParameter("email");

        String token = Integer.toString(new java.security.SecureRandom().nextInt(1000000));

        response.getWriter().println("reset link for " + email + " token " + token);
    }
}
