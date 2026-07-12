// correct pattern: secret loaded from the environment, never a literal
const stripeKey = process.env.STRIPE_SECRET_KEY;

export function charge(amount) {
  return fetch("https://api.stripe.com/v1/charges", {
    headers: { Authorization: `Bearer ${stripeKey}` },
    body: new URLSearchParams({ amount }),
  });
}
