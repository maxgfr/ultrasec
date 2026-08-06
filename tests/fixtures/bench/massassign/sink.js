function apply(model, body) {
  // Every field the request carries is bound, including `role` and `isAdmin`.
  return model.setAttributes(body);
}
module.exports = { apply };
