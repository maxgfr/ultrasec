const mysql = require("mysql");

const conn = mysql.createConnection({ host: "localhost" });

// Final hop: the raw SQL sink. `sql` arrives already concatenated upstream.
function runQuery(sql) {
  return conn.query(sql);
}

module.exports = { runQuery };
