const db = require("db");
function lookup(v) {
  return db.query("SELECT * FROM users WHERE id = " + v);
}
module.exports = { lookup };
