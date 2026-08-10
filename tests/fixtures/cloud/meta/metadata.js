async function creds() {
  const r = await fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
  return r.text();
}
module.exports = { creds };
