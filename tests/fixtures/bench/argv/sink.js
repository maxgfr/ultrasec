// An argv array is not a safe harbour: the attacker controls an ARGUMENT, and
// plenty of ordinary binaries execute code for you when they get the right one
// (`git --upload-pack=`, `curl -o`, `ssh -oProxyCommand=`).
const { execFile } = require("child_process");
function run(ref) {
  return execFile("git", ["fetch", ref]);
}
module.exports = { run };
