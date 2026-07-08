function ingest(req) {
  const doc = req.body.json;
  return JSON.parse(doc);
}
module.exports = { ingest };
