const { lookup } = require("./sink");
function handle(req) {
  const input = req.query.id;
  return lookup(input);
}
module.exports = { handle };
