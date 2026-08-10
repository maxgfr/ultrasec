const https=require("https");
function call(){
  return https.request({ host: "api.example.com", rejectUnauthorized: false });
}
module.exports={call};
