export function trace(x: number): number {
  console.trace("value", x);
  return x * 2;
}
