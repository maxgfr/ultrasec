import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Safe {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    // Validated against a strict shape; no expression is built from it here.
    boolean ok = name != null && name.matches("[A-Za-z0-9_]{1,32}");
    response.setStatus(ok ? 200 : 400);
  }
}
