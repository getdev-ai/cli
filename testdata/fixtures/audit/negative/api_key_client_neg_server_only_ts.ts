// server-only variable name (no NEXT_PUBLIC_/VITE_/REACT_APP_ prefix) — not
// bundler-exposed, so this rule stays silent (audit/hardcoded-secret is the
// rule that covers the hardcoded-literal concern itself)
const STRIPE_SECRET_KEY: string = "sk_live_FAKEFAKEFAKE1234";

export function charge(): string {
  return STRIPE_SECRET_KEY;
}
