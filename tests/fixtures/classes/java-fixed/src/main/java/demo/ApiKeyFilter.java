package demo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ApiKeyFilter {
    boolean allowed(String provided) {
        byte[] expected = System.getenv("API_KEY").getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(provided.getBytes(StandardCharsets.UTF_8), expected);
    }
}
