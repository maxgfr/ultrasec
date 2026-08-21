using System.Diagnostics;

public class C {
  public void Go(string q) {
    Process.Start("sh", "-c " + q);
  }
}
