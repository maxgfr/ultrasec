const fs = require("fs");
function readDoc(v) {
  return fs.readFileSync("/srv/docs/" + v);
}
module.exports = { readDoc };
