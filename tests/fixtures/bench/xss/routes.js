const { renderSearch } = require("./sink");
function handle(req, res) {
  const q = req.query.q;
  return renderSearch(res, q);
}
module.exports = { handle };
