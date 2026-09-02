import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

public class Safe {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    // The template is fixed; the input is a context VALUE the template renders.
    VelocityContext context = new VelocityContext();
    context.put("name", name);
    Template t = Velocity.getTemplate("greeting.vm");
    StringWriter writer = new StringWriter();
    t.merge(context, writer);
    response.setContentLength(writer.toString().length());
  }
}
