const { lookup } = require("./sink");
function handler(req, res) {
  const user = req.query.user;
  return res.json(lookup(global.doc, user));
}
module.exports = { handler };
