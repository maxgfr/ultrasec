const { evaluate } = require("./sink");
function handle(req) {
  const input = req.query.expr;
  return evaluate(input);
}
module.exports = { handle };
