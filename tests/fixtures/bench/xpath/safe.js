function safe(req) {
  const user = req.query.user;
  // Never reaches an XPath expression.
  return require("./audit").record(String(user));
}
module.exports = { safe };
