using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class SearchController : Controller
{
    public void Index(HttpRequest Request, HttpResponse Response)
    {
        string q = Request.Query["q"];
        Response.WriteAsync("<h1>Results for " + q + "</h1>");
    }
}
