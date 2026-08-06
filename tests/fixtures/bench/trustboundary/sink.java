import javax.servlet.http.HttpServletRequest;

public class Store {
  // Raw request data crosses into session state without validation; everything
  // downstream reads it as if the application had put it there.
  public void keep(HttpServletRequest request, String value) {
    request.getSession().setAttribute("pref", value);
  }
}
