function safe(req) {
  const input = req.query.name;
  return require("child_process").execFile("report", ["--for", input]);
}
module.exports = { safe };
