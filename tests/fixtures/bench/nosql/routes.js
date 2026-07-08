const { lookup } = require("./sink");
function handle(req) {
  const input = req.query.filter;
  return lookup(input);
}
module.exports = { handle };
