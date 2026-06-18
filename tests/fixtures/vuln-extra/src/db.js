const client = require("./client");

// A thin data-access wrapper; `find` here is the NoSQL sink the catalog matches.
function find(filter) {
  return client.collection("users").find(filter);
}

module.exports = { find };
