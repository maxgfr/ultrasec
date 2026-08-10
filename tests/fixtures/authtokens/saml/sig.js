const { SAML } = require("@node-saml/node-saml");
const sp = new SAML({ wantAssertionsSigned: false });
module.exports = sp;
