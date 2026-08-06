const { matchPattern } = require("./sink");
function handler(req, res) {
  const pattern = req.query.pattern;
  return res.json(matchPattern(pattern, "abc"));
}
module.exports = { handler };
