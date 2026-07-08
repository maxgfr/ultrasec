const fs = require("fs");
function safe() {
  return fs.readFileSync("/srv/docs/index.html");
}
module.exports = { safe };
