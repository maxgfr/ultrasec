// The Secure flag follows the deployment's scheme: set, not missing.
function clearSession(response, baseUrl, name) {
  const isHttps = baseUrl.startsWith("https://");
  response.cookies.set(name, "", { expires: new Date(0), secure: isHttps, httpOnly: true, sameSite: "lax" });
}
module.exports = { clearSession };
