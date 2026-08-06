function safe(req) {
  const body = req.body;
  // Explicit field allow-list; nothing else can be set.
  return { displayName: String(body.displayName || "") };
}
module.exports = { safe };
