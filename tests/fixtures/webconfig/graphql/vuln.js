const { ApolloServer } = require("apollo-server");
const server = new ApolloServer({
  introspection: true,
  playground: true,
});
module.exports = server;
