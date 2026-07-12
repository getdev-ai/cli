// W3: eval() applied to the RESULT of another call — the JS call-expression
// matcher that previously had no positive fixture.
function runExpression() {
  return eval(getUserCode());
}
