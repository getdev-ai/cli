// W3: eval(<identifier>) in TypeScript — the entire TS eval query was
// previously unexercised.
export function runExpression(userInput: string): unknown {
  return eval(userInput);
}
