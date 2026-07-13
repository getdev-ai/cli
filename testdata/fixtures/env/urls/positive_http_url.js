// positive: a plain http(s) URL assigned to an identifier is hardcoded
// deployment config that `env --include-urls` extracts to `.env`.
const apiBase = "https://api.example.com/v1";

export function endpoint(path) {
  return apiBase + path;
}
