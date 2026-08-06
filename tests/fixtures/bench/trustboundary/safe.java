import javax.servlet.http.HttpServletRequest;

public class Safe {
  public void handle(HttpServletRequest request) {
    // The value is measured and discarded; it crosses no boundary.
    String pref = request.getParameter("pref");
    int n = pref.length();
    store(n);
  }

  private void store(int n) {}
}
