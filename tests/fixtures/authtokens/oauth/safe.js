function authorizeUrl(state, challenge, cb){
  return "https://idp.example.com/authorize?response_type=code&state=" + state + "&code_challenge=" + challenge;
}
function isAllowed(redirectUri){ return redirectUri === "https://app.example.com/cb"; }
module.exports={authorizeUrl, isAllowed};
