// PREC-04: a deployment endpoint URL assigned to a secret-suggesting name
// (TOKEN_URL) — deployment config, not a hardcoded secret. The value SHAPE
// (an http(s) URL) is deployment config; a credentialed URL would still flag
// via env --include-urls' classify_url path.
const TOKEN_URL = "https://oauth.platform.example.com/oauth2/v1/tokens/bearer";

module.exports = { TOKEN_URL };
