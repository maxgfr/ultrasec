function find(client) {
  return client.search("(uid=admin)");
}
module.exports = { find };
