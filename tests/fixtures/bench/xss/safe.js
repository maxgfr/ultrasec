function safe(req) {
  const input = req.query.q;
  return res.json({ q: input });
}
module.exports = { safe };
