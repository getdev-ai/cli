// placeholder value, not a real secret — must not fire
const apiKey: string = "YOUR-API-KEY-HERE";

export function configured(): boolean {
  return apiKey.length > 0;
}
