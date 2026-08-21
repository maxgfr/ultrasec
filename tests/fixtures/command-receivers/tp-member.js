const child_process = require("child_process");
export const KALI = "kali";
function handler(req) {
  return child_process.exec("report --for " + req.query.v);
}
module.exports = { handler, KALI };
