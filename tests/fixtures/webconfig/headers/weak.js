function harden(res){
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'");
  res.setHeader("X-Frame-Options", "ALLOWALL");
  res.setHeader("Strict-Transport-Security", "max-age=0");
  res.setHeader("Referrer-Policy", "unsafe-url");
}
module.exports={harden};
