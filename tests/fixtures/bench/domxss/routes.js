const { render } = require("./sink");
function boot() {
  const frag = location.hash.slice(1);
  render(document.body, frag);
}
module.exports = { boot };
