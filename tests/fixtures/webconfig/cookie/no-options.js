function login(res, token){
  res.cookie("sid", token);
}
module.exports={login};
