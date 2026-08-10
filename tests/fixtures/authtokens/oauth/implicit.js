function authorizeUrl(cb){
  return "https://idp.example.com/authorize?response_type=token&client_id=abc&redirect_uri=" + encodeURIComponent(cb);
}
module.exports={authorizeUrl};
