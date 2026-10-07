const router = require("express").Router();
const { User } = require("./models");

router.get("/export/users", async (req, res) => {
  const page = Number(req.query.page ?? 0);
  const rows = await User.findAll({ limit: 500, offset: page * 500 });
  res.json(rows);
});

module.exports = router;
