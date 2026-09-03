package com.example.crypto;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** Encrypts a request-supplied note with a broken primitive. */
public class WeakCipher {

    public void encrypt(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String note = request.getParameter("note");

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
        javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);

        byte[] out = cipher.doFinal(note.getBytes("UTF-8"));
        response.getWriter().println(java.util.Base64.getEncoder().encodeToString(out));
    }
}
