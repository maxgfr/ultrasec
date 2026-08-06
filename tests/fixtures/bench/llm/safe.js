function safe(req) {
  const question = req.body.question;
  // Stays data: stored and rendered as text, never sent to a model.
  return require("./store").save({ question: String(question) });
}
module.exports = { safe };
