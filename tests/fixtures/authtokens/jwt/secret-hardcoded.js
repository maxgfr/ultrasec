const jwt=require("jsonwebtoken");
function sign(p){ return jwt.sign(p, "9f8s7d6f5g4h3j2k1l0zxcvbnmqwerty", { algorithm: "HS256" }); }
module.exports={sign};
