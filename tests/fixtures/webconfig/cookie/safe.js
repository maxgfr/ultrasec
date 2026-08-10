function login(res, token){
  res.clearCookie("old");
  res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "lax" });
}
module.exports={login};
