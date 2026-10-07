const express = require("express");

module.exports = function configure(app) {
  app.use(express.json());
};
