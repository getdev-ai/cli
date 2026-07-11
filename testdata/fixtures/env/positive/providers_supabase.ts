// seeded defects: Supabase key shapes (values are fake, format-only)
// covers supabase-access-token (3) and supabase-secret-key (3) — CLAUDE.md
// hard rule 3 fixture backfill. See C3/03-REVIEW.md: sbp_ is Supabase's
// personal access token, sb_secret_ is the current project secret-key
// format; the service-role key (a JWT) is deliberately not pattern-matched.

export const supabaseAccessTokenA =
  "sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbe1a";
export const supabaseAccessTokenB =
  "sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbe2b";
export const supabaseAccessTokenC =
  "sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbe3c";

export const supabaseSecretKeyA = "sb_secret_FAKEFAKEFAKEFAKEFAA1";
export const supabaseSecretKeyB = "sb_secret_FAKEFAKEFAKEFAKEFAB2";
export const supabaseSecretKeyC = "sb_secret_FAKEFAKEFAKEFAKEFAC3";
