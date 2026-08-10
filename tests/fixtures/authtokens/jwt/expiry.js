const jwt=require("jsonwebtoken");
function verify(t, key){ return jwt.verify(t, key, { algorithms: ["HS256"], ignoreExpiration: true }); }
module.exports={verify};
