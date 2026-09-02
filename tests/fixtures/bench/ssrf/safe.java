import java.net.URI;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Safe {
  private static final Set<String> ALLOWED = Set.of("api.example.com", "cdn.example.com");

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String url = request.getParameter("url");
    // Only the host is inspected; nothing is requested from the input here.
    URI parsed = URI.create(url);
    boolean ok = ALLOWED.contains(parsed.getHost());
    response.setStatus(ok ? 200 : 400);
  }
}
