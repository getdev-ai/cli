export function add(a: number, b: number): number {
  return a + b;
}

function computeUnusedTotal(values: number[]): number {
  let total = 0;
  for (const value of values) {
    total += value;
  }
  return total;
}
