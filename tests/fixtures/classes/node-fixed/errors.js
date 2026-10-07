const errorhandler = require("errorhandler");

module.exports = function configure(app) {
  if (process.env.NODE_ENV === "development") app.use(errorhandler());
};
