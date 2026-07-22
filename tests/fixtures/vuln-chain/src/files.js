const { readFileSync } = require("node:fs");

// Path-traversal sink: tainted `doc` is used as a filesystem path unconfined.
function readDoc(doc) {
  return readFileSync("docs/" + doc, "utf8");
}

module.exports = { readDoc };
