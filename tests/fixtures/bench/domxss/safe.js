function safe() {
  const frag = location.hash.slice(1);
  // textContent never parses markup.
  document.title = String(frag).slice(0, 40);
}
module.exports = { safe };
