const router = require("express").Router();
const { User } = require("./models");

router.get("/export/users", async (req, res) => {
  const rows = await User.findAll();
  res.json(rows);
});

module.exports = router;
