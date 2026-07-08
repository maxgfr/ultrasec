const { parseXml } = require("./xml");
function ingest(req) {
  const doc = req.body.xml;
  return parseXml(doc);
}
module.exports = { ingest };
