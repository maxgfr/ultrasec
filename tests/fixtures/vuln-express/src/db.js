const sqlite = require("./sqlite");

// Tainted `id` reaches a raw SQL sink via string concatenation — cross-file sink.
function getUser(id) {
  const sql = "SELECT * FROM users WHERE id = " + id;
  return sqlite.query(sql);
}

// Sanitized sibling: parameterized query, no concatenation. Must NOT be flagged.
function getUserSafe(id) {
  return sqlite.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { getUser, getUserSafe };
