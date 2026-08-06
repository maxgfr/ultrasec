const FIXED = /^[a-z0-9_-]{1,32}$/;
function safe(req) {
  const name = req.query.name;
  // Fixed pattern; the untrusted value is the SUBJECT, not the pattern.
  return FIXED.test(String(name));
}
module.exports = { safe };
