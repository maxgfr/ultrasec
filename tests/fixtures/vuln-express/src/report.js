const { execSync } = require("child_process");

// Tainted `name` reaches a shell sink (command injection) across files.
function runReport(name) {
  return execSync("generate-report --for " + name).toString();
}

module.exports = { runReport };
