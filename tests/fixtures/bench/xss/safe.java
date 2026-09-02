import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Safe {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String q = request.getParameter("q");
    // Formatted into a string, never written to the response body.
    String label = String.format("q=%s", q);
    response.setContentLength(label.length());
    response.setContentType("text/plain");
  }
}
