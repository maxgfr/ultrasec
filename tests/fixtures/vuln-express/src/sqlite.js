// A thin DB wrapper. `query` is the raw SQL sink ultrasec's catalog flags.
function query(sql, params) {
  // pretend to talk to a database
  return { sql, params: params || [] };
}

module.exports = { query };
