import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Vuln {
  private InitialDirContext ctx;

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String uid = request.getParameter("uid");
    SearchControls sc = new SearchControls();
    ctx.search("ou=people,dc=example,dc=com", "(uid=" + uid + ")", sc);
    response.setStatus(200);
  }
}
