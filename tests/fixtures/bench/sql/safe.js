const db = require("db");
function safe() {
  return db.query("SELECT * FROM users WHERE id = ?", ["1"]);
}
module.exports = { safe };
