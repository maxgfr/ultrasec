const db = require("db");
function lookup(v) {
  return db.find(v);
}
module.exports = { lookup };
