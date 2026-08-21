const spawn = require("child_process").spawn;
function handler(req) {
  return spawn("sh", ["-c", req.query.v]);
}
module.exports = { handler };
