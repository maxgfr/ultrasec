function login(res, token){
  res.cookie("sid", token, { path: "/" });
}
module.exports={login};
