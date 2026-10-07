package demo;

public class ApiKeyFilter {
    boolean allowed(String provided) {
        return provided.equals(System.getenv("API_KEY"));
    }
}
