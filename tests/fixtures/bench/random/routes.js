const { mintToken } = require("./sink");
function handler(req, res) {
  const email = req.query.email;
  return res.json({ email, token: mintToken() });
}
module.exports = { handler };
