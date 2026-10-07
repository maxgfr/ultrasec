const Fastify = require("fastify");

const app = Fastify({ logger: true });
app.listen({ port: 3000 });
