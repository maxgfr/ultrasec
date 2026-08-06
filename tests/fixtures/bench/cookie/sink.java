import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class Setter {
  // No Secure / HttpOnly / SameSite: the value travels in clear and is readable
  // from script.
  public void put(HttpServletResponse response, String value) {
    response.addCookie(new Cookie("pref", value));
  }
}
