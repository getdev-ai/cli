// must NOT fire: Stripe near-misses — one char short of the minimum body
// length either pattern requires, so neither regex matches.
const stripeSecretTooShort = "sk_live_FAKEFAKEFAKEFAK";
const stripeRestrictedTooShort = "rk_live_FAKEFAKEFAKEFAK";
const stripeRestrictedTestMode = "rk_test_FAKEFAKEFAKEG7H8";
