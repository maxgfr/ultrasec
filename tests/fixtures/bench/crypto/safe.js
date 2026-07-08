const { sha256 } = require("./hash");
function store(req) {
  const pw = req.body.password;
  return sha256(pw);
}
module.exports = { store };
