const { fetchUrl } = require("./sink");
function handle(req) {
  const input = req.query.url;
  return fetchUrl(input);
}
module.exports = { handle };
