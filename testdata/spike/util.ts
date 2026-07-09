export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

export const identity = <T>(x: T): T => x;
