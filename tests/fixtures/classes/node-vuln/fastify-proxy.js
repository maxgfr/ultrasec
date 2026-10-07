const Fastify = require("fastify");
const helmet = require("@fastify/helmet");

const app = Fastify({ trustProxy: true });
app.register(helmet);
module.exports = app;
