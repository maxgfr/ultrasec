const { randomBytes } = require("crypto");
function safe(req) {
  const email = req.query.email;
  // CSPRNG: unpredictable by construction.
  return { email, token: randomBytes(32).toString("hex") };
}
module.exports = { safe };
