const { readDoc } = require("./sink");
function handle(req) {
  const input = req.query.file;
  return readDoc(input);
}
module.exports = { handle };
