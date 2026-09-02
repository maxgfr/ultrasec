using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    public IActionResult Login(HttpRequest Request)
    {
        string next = Request.Query["next"];
        // LocalRedirect refuses anything that is not a local path.
        return LocalRedirect("/home");
    }
}
