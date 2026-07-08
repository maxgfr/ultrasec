function handle(req, res) {
  const code = req.query.code;
  return res.status(code);
}
module.exports = { handle };
