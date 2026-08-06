import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Routes {
  public void handle(HttpServletRequest request, HttpServletResponse response) {
    String pref = request.getParameter("pref");
    new Setter().put(response, pref);
  }
}
