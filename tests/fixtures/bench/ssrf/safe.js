function safe(req) {
  const input = req.query.key;
  return require("./cache").get(input);
}
module.exports = { safe };
