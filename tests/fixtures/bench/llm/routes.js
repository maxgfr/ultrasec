const { ask } = require("./sink");
function handler(req, res) {
  const question = req.body.question;
  return res.json(ask(question));
}
module.exports = { handler };
