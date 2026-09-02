using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Http;

public class StateController
{
    public object Restore(HttpRequest Request)
    {
        string data = Request.Form["state"];
        var bf = new BinaryFormatter();
        var stream = new MemoryStream(Convert.FromBase64String(data));
        return bf.Deserialize(stream);
    }
}
