const child_process = require("child_process");
function runReport(v) {
  return child_process.execSync("report --for " + v);
}
module.exports = { runReport };
