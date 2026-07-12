// seeded defect: live Stripe secret key hardcoded in source (value is fake)
const stripeKey = "sk_live_FAKEFAKEFAKE1234";

export function charge(amount) {
  return fetch("https://api.stripe.com/v1/charges", {
    headers: { Authorization: `Bearer ${stripeKey}` },
    body: new URLSearchParams({ amount }),
  });
}
