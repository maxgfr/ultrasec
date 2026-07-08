function safe(req) {
  const input = req.query.id;
  return require("./db").findById(input);
}
module.exports = { safe };
