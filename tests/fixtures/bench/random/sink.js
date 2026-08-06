// A password-reset token from a non-cryptographic RNG is guessable.
function mintToken() {
  return Math.random().toString(36).slice(2);
}
module.exports = { mintToken };
