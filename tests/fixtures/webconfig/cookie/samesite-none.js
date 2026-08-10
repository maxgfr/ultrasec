function login(res, token){
  res.cookie("sid", token, { httpOnly: true, sameSite: "none" });
}
module.exports={login};
