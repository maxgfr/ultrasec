const jwt=require("jsonwebtoken");
const SECRET = process.env.JWT_SECRET;
function sign(p){ return jwt.sign(p, SECRET, { algorithm: "HS256", expiresIn: "15m" }); }
function verify(t){ return jwt.verify(t, SECRET, { algorithms: ["HS256"] }); }
module.exports={sign, verify};
