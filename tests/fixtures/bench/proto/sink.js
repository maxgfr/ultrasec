const _ = require("_");
function applyConfig(v) {
  return _.merge({}, v);
}
module.exports = { applyConfig };
