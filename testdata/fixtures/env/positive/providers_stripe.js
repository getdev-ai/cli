// seeded defects: additional Stripe key shapes (values are fake, format-only)
// covers stripe-live-secret-key (2 more, on top of stripe_live.js) and
// stripe-live-restricted-key (3) — CLAUDE.md hard rule 3 fixture backfill.

const stripeSecretBackup = "sk_live_FAKEFAKEFAKEA1B2";
const stripeSecretRotated = "sk_live_FAKEFAKEFAKEC3D4";

const stripeRestrictedA = "rk_live_FAKEFAKEFAKEG7H8";
const stripeRestrictedB = "rk_live_FAKEFAKEFAKEI9J0";
const stripeRestrictedC = "rk_live_FAKEFAKEFAKEK1L2";
