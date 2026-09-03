package com.example.crypto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** The same shape, with the primitives the catalog note calls safe. */
public class StrongCipher {

    public void encrypt(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String note = request.getParameter("note");

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, nonce()));

        byte[] out = cipher.doFinal(note.getBytes("UTF-8"));
        response.getWriter().println(java.util.Base64.getEncoder().encodeToString(out));
    }

    private byte[] nonce() {
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }
}
