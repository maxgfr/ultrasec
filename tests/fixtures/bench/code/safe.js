function safe(req) {
  const input = req.query.expr;
  return JSON.parse(input);
}
module.exports = { safe };
