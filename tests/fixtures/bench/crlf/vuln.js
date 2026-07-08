function handle(req, res) {
  const lang = req.query.lang;
  return res.setHeader("Content-Language", lang);
}
module.exports = { handle };
