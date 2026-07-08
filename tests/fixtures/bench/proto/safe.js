function safe(req) {
  const input = req.query.body;
  return Object.assign({}, input);
}
module.exports = { safe };
