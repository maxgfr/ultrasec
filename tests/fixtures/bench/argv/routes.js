const { run } = require("./sink");
function handler(req, res) {
  const ref = req.query.ref;
  return res.json(run(ref));
}
module.exports = { handler };
