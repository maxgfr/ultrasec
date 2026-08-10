function authorizeUrl(cb){
  return "https://idp.example.com/authorize?response_type=code&client_id=abc&redirect_uri=" + cb;
}
module.exports={authorizeUrl};
