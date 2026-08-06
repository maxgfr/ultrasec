function safe(req) {
  const input = req.query.name;
  // The value is formatted for the report title and never reaches a process
  // call. The argv-array form used to be the "safe" counterpart here; it moved
  // to bench/argv, where it is the VULNERABLE case — an argv array stops shell
  // metacharacters, not option injection.
  return require("./format").title(input);
}
module.exports = { safe };
