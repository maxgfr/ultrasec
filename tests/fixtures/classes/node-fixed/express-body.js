const express = require("express");

module.exports = function configure(app) {
  app.use(express.json({ limit: "100kb" }));
};
