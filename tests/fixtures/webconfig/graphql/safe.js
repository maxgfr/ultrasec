const { ApolloServer } = require("apollo-server");
const server = new ApolloServer({
  introspection: false,
});
module.exports = server;
