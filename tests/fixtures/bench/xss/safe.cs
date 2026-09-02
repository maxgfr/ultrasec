using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class SearchController : Controller
{
    public IActionResult Index(HttpRequest Request)
    {
        string q = Request.Query["q"];
        // Encoded, and returned through a typed result the framework encodes again.
        string safe = HttpUtility.HtmlEncode(q);
        return Content(safe, "text/plain");
    }
}
