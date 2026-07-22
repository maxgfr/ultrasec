const axios = require("axios");
const cache = new Map();

// SSRF sink: member call `axios.get(url)` — matched only via the receiver-gated
// rule (requireReceiver). The bare `get()` below is a plain cache getter and
// must NOT be treated as an HTTP sink.
function fetchUrl(url) {
  return axios.get(url);
}

function get(key) {
  return cache.get(key);
}

module.exports = { fetchUrl, get };
