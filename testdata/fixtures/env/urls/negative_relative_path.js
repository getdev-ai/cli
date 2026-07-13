// negative: a relative filesystem path has no scheme+host — it is NOT a URL
// and must never be extracted, even with --include-urls on.
const configPath = "./config/settings.json";

export function load() {
  return configPath;
}
