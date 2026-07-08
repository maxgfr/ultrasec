const { runReport } = require("./sink");
function handle(req) {
  const input = req.query.name;
  return runReport(input);
}
module.exports = { handle };
