// prefixed correctly, but the value is a placeholder, not a real
// provider-key-shaped literal
const NEXT_PUBLIC_API_KEY = "your-api-key-here";

export function configured() {
  return NEXT_PUBLIC_API_KEY.length > 0;
}
