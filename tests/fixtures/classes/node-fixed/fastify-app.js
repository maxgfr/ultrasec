const Fastify = require("fastify");
const helmet = require("@fastify/helmet");

const app = Fastify({ logger: true });
app.register(helmet);
app.listen({ port: 3000 });
