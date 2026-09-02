using System.Text.Json;
using Microsoft.AspNetCore.Http;

public class StateController
{
    public int Restore(HttpRequest Request)
    {
        string data = Request.Form["state"];
        // A data-only JSON document: no type information, no gadget chain.
        using var doc = JsonDocument.Parse(data);
        return doc.RootElement.GetProperty("page").GetInt32();
    }
}
