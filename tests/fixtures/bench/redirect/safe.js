function handle(req, res) {
  const next = req.query.next;
  return res.render("home", { next });
}
module.exports = { handle };
