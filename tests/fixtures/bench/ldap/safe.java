import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Safe {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String uid = request.getParameter("uid");
    // Validated against a strict shape; no filter is built from it here.
    boolean ok = uid != null && uid.matches("[A-Za-z0-9._-]{1,64}");
    response.setStatus(ok ? 200 : 400);
  }
}
