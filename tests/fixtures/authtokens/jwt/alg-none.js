const jwt=require("jsonwebtoken");
function verify(t, key){ return jwt.verify(t, key, { algorithms: ["none"] }); }
module.exports={verify};
