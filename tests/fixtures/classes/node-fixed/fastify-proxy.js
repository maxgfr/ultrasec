const Fastify = require("fastify");
const helmet = require("@fastify/helmet");

const app = Fastify({ trustProxy: "10.0.0.1" });
app.register(helmet);
module.exports = app;
