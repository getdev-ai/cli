// W2: a hardcoded provider secret in a .tsx component (value is fake) — the
// secret matcher must also run on .tsx files.
const stripeKey: string = "sk_live_FAKEFAKEFAKE1234";

export function Pay(): JSX.Element {
  return <button data-key={stripeKey}>Pay</button>;
}
