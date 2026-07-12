// seeded defect: NEXT_PUBLIC_ prefix inlines this Stripe secret into the
// client bundle (value is fake)
const NEXT_PUBLIC_STRIPE_KEY = "sk_live_FAKEFAKEFAKE1234";

export function stripeClient() {
  return { apiKey: NEXT_PUBLIC_STRIPE_KEY };
}
