const { SAML } = require("@node-saml/node-saml");
const sp = new SAML({ wantAssertionsSigned: true, wantMessageSigned: true });
module.exports = sp;
