const { execSync } = require("child_process");

// Command-injection sink: tainted `name` is concatenated into a shell command.
function buildReport(name) {
  return execSync("generate-report --for " + name).toString();
}

module.exports = { buildReport };
