using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    public IActionResult Login(HttpRequest Request)
    {
        string next = Request.Query["next"];
        return Redirect(next);
    }
}
