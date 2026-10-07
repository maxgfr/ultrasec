function isAdmin(req) {
  const provided = req.get("x-admin-token");
  return provided === process.env.ADMIN_API_TOKEN;
}
module.exports = { isAdmin };
