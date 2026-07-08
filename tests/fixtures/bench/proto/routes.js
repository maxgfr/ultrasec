const { applyConfig } = require("./sink");
function handle(req) {
  const input = req.query.body;
  return applyConfig(input);
}
module.exports = { handle };
