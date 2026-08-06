// The commonest DOM XSS shape in the wild — and an ASSIGNMENT, so a call-based
// catalog can never see it.
function render(el, html) {
  el.innerHTML = html;
}
module.exports = { render };
