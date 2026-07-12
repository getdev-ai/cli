// W3: eval(<member expression>) in TypeScript.
export function runExpression(req: { body: { code: string } }): unknown {
  return eval(req.body.code);
}
