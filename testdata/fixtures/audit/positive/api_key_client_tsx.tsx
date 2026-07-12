// W2: a .tsx React component is TypeScript+JSX and must be AST-scanned.
// seeded defect: both a NEXT_PUBLIC_ variable and a VITE_ object key inline
// a provider secret into the client bundle (values are fake).
const NEXT_PUBLIC_STRIPE_KEY = "sk_live_FAKEFAKEFAKE1234";

const config = {
  VITE_GITHUB_TOKEN: "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
};

export function Checkout(): JSX.Element {
  return <button data-key={NEXT_PUBLIC_STRIPE_KEY} data-cfg={config.VITE_GITHUB_TOKEN}>Pay</button>;
}
