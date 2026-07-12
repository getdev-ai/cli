// correct pattern: value pulled from the build-time env, no literal secret
// baked into the source itself
const NEXT_PUBLIC_STRIPE_KEY = process.env.NEXT_PUBLIC_STRIPE_KEY;

export function stripeClient() {
  return { apiKey: NEXT_PUBLIC_STRIPE_KEY };
}
