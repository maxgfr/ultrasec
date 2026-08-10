function isAllowed(redirectUri){
  return redirectUri.startsWith("https://app.example.com");
}
module.exports={isAllowed};
