const db = require("./db");
const _ = require("lodash");

// NoSQL injection: untrusted filter object reaches a Mongo query (CWE-943).
function search(req, res) {
  const filter = req.query.filter;
  return db.find(filter);
}

// Prototype pollution: untrusted body deep-merged into an object (CWE-1321).
function update(req, res) {
  const target = {};
  _.merge(target, req.body);
  return target;
}

module.exports = { search, update };
