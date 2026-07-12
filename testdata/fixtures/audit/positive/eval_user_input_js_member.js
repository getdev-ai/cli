function runExpression(req) {
  return eval(req.body.code);
}
