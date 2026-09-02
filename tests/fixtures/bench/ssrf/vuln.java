import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.client.RestTemplate;

public class Vuln {
  private final RestTemplate restTemplate = new RestTemplate();

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String url = request.getParameter("url");
    String body = restTemplate.getForObject(url, String.class);
    response.setContentLength(body.length());
  }
}
