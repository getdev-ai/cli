// W2: all three JS/TS eval() non-literal shapes (identifier, member access,
// call result) exercised from a .tsx component.
export function Danger({ userInput, req }: { userInput: string; req: { body: { code: string } } }): JSX.Element {
  const a = eval(userInput);
  const b = eval(req.body.code);
  const c = eval(getCode());
  return <pre>{String(a) + String(b) + String(c)}</pre>;
}
