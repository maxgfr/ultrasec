const cp = require("child_process");
const { execSync, spawnSync } = require("child_process");
function handler(req) {
  const c = req.query.c;
  cp.exec(c);
  cp.spawn("sh", ["-c", c]);
  execSync(c);
  spawnSync("sh", ["-c", c]);
}
module.exports = { handler };
