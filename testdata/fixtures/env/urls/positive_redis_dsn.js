// positive: a Redis DSN (known connection-string scheme) without embedded
// credentials is still a hardcoded endpoint that belongs in `.env`.
const cacheUrl = "redis://cache.internal:6379/0";

export function cache() {
  return cacheUrl;
}
