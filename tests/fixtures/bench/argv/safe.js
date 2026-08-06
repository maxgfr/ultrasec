const { execFile } = require("child_process");
function safe() {
  // Constant argv: nothing attacker-controlled reaches the process at all.
  return execFile("git", ["status", "--porcelain"]);
}
module.exports = { safe };
