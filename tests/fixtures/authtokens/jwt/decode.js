const jwt=require("jsonwebtoken");
function read(t){ return jwt.decode(t); }
module.exports={read};
