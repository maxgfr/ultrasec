const { runQuery } = require("./db");

// Middle hop of the 3-file SQLi chain: concatenates the tainted id into SQL.
function lookupUser(id) {
  const sql = "SELECT * FROM users WHERE id = " + id;
  return runQuery(sql);
}

module.exports = { lookupUser };
