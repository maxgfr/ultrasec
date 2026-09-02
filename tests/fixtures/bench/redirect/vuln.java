import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Vuln {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String next = request.getParameter("next");
    response.sendRedirect(next);
  }
}
