function handle(req, res) {
  const next = req.query.next;
  return res.redirect(next);
}
module.exports = { handle };
