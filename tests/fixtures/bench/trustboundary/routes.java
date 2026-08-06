import javax.servlet.http.HttpServletRequest;

public class Routes {
  public void handle(HttpServletRequest request) {
    String pref = request.getParameter("pref");
    new Store().keep(request, pref);
  }
}
