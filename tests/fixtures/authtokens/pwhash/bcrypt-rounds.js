const bcrypt=require("bcrypt");
function hash(pw){ return bcrypt.hashSync(pw, 6); }
module.exports={hash};
