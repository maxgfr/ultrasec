const https=require("https");
function call(){
  return https.request({ host: "api.example.com", rejectUnauthorized: true });
}
module.exports={call};
