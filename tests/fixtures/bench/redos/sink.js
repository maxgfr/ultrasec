function matchPattern(pattern, text) {
  // A pattern the attacker chose: nested quantifiers burn CPU on any input.
  return new RegExp(pattern).test(text);
}
module.exports = { matchPattern };
