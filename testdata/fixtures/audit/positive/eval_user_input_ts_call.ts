// W3: eval(<call expression>) in TypeScript.
export function runExpression(): unknown {
  return eval(getUserCode());
}
