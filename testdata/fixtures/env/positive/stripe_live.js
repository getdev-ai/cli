// seeded defect: live Stripe key hardcoded (value is fake)
const stripeKey = "sk_live_FAKEFAKEFAKE1234";

export function charge(amount) {
  return fetch("https://api.stripe.com/v1/charges", {
    headers: { Authorization: `Bearer ${stripeKey}` },
    body: new URLSearchParams({ amount }),
  });
}

// fixture note: fake key bodies stay under 24 chars so GitHub push
// protection (which matches real Stripe key lengths) never blocks
// contributor pushes; getdev's own pattern fires from 16 chars.
