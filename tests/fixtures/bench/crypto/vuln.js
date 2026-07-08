const { md5 } = require("./hash");
function store(req) {
  const pw = req.body.password;
  return md5(pw);
}
module.exports = { store };
