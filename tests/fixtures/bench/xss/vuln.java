import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Vuln {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String q = request.getParameter("q");
    response.getWriter().format("<h1>Results for %s</h1>", q);
  }
}
