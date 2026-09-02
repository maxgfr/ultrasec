import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Safe {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    // The destination is fixed; the parameter only selects a status message.
    response.setStatus(302);
    response.setContentType("text/plain");
  }
}
