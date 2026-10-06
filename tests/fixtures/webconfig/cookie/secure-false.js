function login(res, token) {
  res.cookie("sid", token, { httpOnly: true, secure: false, sameSite: "lax" });
}
module.exports = { login };
