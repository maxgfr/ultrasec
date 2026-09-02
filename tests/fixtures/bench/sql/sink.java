package app;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserDao {
  private Connection conn;

  public String lookup(String id) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    return rs.getString(1);
  }
}
