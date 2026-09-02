package app;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String id = request.getParameter("id");
    // Coerced to an integer; no statement is built from the string.
    int n = Integer.parseInt(id);
    response.setStatus(n > 0 ? 200 : 400);
  }
}
