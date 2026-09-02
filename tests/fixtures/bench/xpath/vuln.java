import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;

public class Vuln {
  private XPath xpath;

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    XPathExpression expr = xpath.compile("//user[@name='" + name + "']/password");
    response.setStatus(expr == null ? 500 : 200);
  }
}
