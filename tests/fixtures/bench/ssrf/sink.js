const axios = require("axios");
function fetchUrl(v) {
  return axios.get(v);
}
module.exports = { fetchUrl };
