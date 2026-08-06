const OpenAI = require("openai");
const client = new OpenAI();
// Untrusted text concatenated into a prompt. The model cannot separate
// instructions from data, so the attacker steers whatever the output drives.
function ask(question) {
  return client.chat.completions.create({
    messages: [{ role: "user", content: "Answer briefly: " + question }],
  });
}
module.exports = { ask };
