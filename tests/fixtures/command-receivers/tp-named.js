const { exec } = require("child_process");
function handler(req) {
  return exec("report --for " + req.query.v);
}
module.exports = { handler };
