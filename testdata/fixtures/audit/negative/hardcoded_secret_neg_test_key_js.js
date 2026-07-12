// Stripe TEST-mode key — by design, never flagged as a live secret
const stripeTestKey = "sk_test_FAKEFAKEFAKE1234";

export function chargeInTestMode(amount) {
  return fetch("https://api.stripe.com/v1/charges", {
    headers: { Authorization: `Bearer ${stripeTestKey}` },
    body: new URLSearchParams({ amount }),
  });
}
