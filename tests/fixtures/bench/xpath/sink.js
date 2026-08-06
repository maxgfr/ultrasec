const xpath = require("xpath");
function lookup(doc, user) {
  // Concatenated into the expression: `' or '1'='1` selects every node.
  const expr = "//user[name=" + user + "]";
  return xpath.selectNodes(doc, expr);
}
module.exports = { lookup };
