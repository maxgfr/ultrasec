async function creds() {
  const r = await fetch("https://api.example.com/v1/creds");
  return r.text();
}
module.exports = { creds };
