const bcrypt=require("bcrypt");
function hash(pw){ return bcrypt.hashSync(pw, 12); }
module.exports={hash};
