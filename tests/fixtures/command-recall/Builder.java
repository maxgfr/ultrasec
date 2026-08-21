import javax.servlet.http.HttpServletRequest;

public class B {
  public void go(HttpServletRequest request) {
    String cmd = request.getParameter("c");
    new ProcessBuilder("sh", "-c", cmd).start();
  }
}
