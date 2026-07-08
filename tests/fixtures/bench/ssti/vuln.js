const { renderString } = require("./engine");
function view(req) {
  const tpl = req.body.tpl;
  return renderString(tpl);
}
module.exports = { view };
