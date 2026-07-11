// must NOT fire: Supabase near-misses — wrong case, too short, and the
// unrelated (client-side, non-secret) publishable-key prefix.
export const supabaseAccessTokenTooShort =
  "sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbee";
export const supabaseAccessTokenUppercaseHex =
  "sbp_DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
export const supabaseSecretKeyTooShort = "sb_secret_FAKEFAKEFAKEFAKEFAK";
export const supabasePublishableKey =
  "sb_publishable_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFA";
