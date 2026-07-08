const { render } = require("./engine");
function view(req) {
  const data = req.body.data;
  return render("page.njk", { data });
}
module.exports = { view };
