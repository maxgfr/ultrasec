import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

public class Vuln {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String tpl = request.getParameter("tpl");
    VelocityContext context = new VelocityContext();
    StringWriter writer = new StringWriter();
    Velocity.evaluate(context, writer, "greeting", tpl);
    response.setContentLength(writer.toString().length());
  }
}
