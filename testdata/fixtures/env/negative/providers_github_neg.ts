// must NOT fire: GitHub token near-misses — one char short of the minimum
// body length either pattern requires.
export const githubTokenTooShort = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK";
export const githubTokenWrongPrefix = "gha_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";
export const githubFineGrainedTooShort =
  "github_pat_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEF";
