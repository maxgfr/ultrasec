const express = require("express");
const logger = require("./logger");

const app = express();

// VULN (log injection, CWE-117 — opt-in `scan --log-hygiene` only): req.query.q
// is untrusted and flows into a log call with no CRLF/newline stripping. The
// DEFAULT sink catalog has no logging callees at all, so this line produces
// ZERO findings under the default (non-opt-in) pipeline.
app.get("/search", (req, res) => {
  const q = req.query.q;
  logger.info(q);
  res.json({ ok: true });
});

// VULN (sensitive-name heuristic, CWE-532 — opt-in): a password-shaped value is
// written straight to a log call. Not a taint flow — a line-content check.
function logLogin(password) {
  logger.info("pw=" + password);
}

// VULN (literal secret pattern, CWE-532 — opt-in): a hard-coded AWS access key
// logged verbatim (SECRET_PATTERNS match, src/logs/secrets.ts).
function logStartupKey() {
  logger.info("startup key=AKIAIOSFODNN7EXAMPLE");
}

// Benign: no untrusted data, no sensitive name/pattern — must NOT be flagged by
// either the CWE-117 or the CWE-532 pass.
function logBoot() {
  logger.info("server started");
}

// Negative control for receiver-gating: a bare, receiver-less invocation of a
// name that otherwise reads like a logger. Every LOG_SINKS rule but PHP's
// error_log is requireReceiver-gated, so this must never match, even under
// --log-hygiene.
function bareLogNegativeControl(secretToken) {
  log(secretToken);
}

module.exports = { logLogin, logStartupKey, logBoot, bareLogNegativeControl };
app.listen(3000);
