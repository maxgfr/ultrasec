function find(req, client) {
  const user = req.query.user;
  return client.search("(uid=" + user + ")");
}
module.exports = { find };
