const errorhandler = require("errorhandler");

module.exports = function configure(app) {
  app.use(errorhandler());
};
