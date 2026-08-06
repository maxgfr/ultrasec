const { apply } = require("./sink");
function handler(req, res) {
  const body = req.body;
  return res.json(apply(global.user, body));
}
module.exports = { handler };
