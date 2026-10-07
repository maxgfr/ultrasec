const { prisma } = require("./db");

module.exports = async function routes(fastify) {
  fastify.get("/public/feed", async () => {
    return prisma.post.findMany();
  });
};
