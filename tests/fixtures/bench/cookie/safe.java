import javax.servlet.http.HttpServletRequest;

public class Safe {
  public void handle(HttpServletRequest request) {
    // Measured and discarded; no cookie is ever written.
    String pref = request.getParameter("pref");
    int n = pref.length();
    store(n);
  }

  private void store(int n) {}
}
