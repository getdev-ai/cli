# getdev.ai — CLI landing site

The public **getdev.ai** landing page for the getdev CLI. A standalone Next.js
static export, deployed to **Cloudflare Pages** (project `getdev-cli-site`),
independent of the getdev gallery (which stays on Railway).

Kept in this repo so the marketing site lives alongside the product it promotes —
a CLI feature and its landing copy change in the same PR. It is **not** part of the
Cargo workspace and is excluded from the getdev self-scan (`.getdev.toml`).

## Develop

```bash
cd site
npm install
npm run dev        # http://localhost:3000
```

## Build

```bash
npm run build      # static export → site/out/
```

## Deploy

Direct upload via wrangler (you must be logged in: `wrangler login`):

```bash
npm run deploy     # next build && wrangler pages deploy out --project-name getdev-cli-site
```

CI auto-deploys on pushes that touch `site/**` (see
`.github/workflows/deploy-site.yml`) once the `CLOUDFLARE_API_TOKEN` repo secret
is set (a token scoped to **Account › Cloudflare Pages › Edit**).

## Load-bearing detail — the install URLs

`public/_redirects` serves the CLI's frozen install URLs:

- `getdev.ai/install.sh`  → `github.com/getdev-ai/cli/releases/latest/download/getdev-installer.sh` (302)
- `getdev.ai/install.ps1` → the PowerShell installer (302)

These must never serve HTML — `curl -fsSL … | sh` pipes the response straight into
a shell. Verify after any deploy:

```bash
curl -sI https://getdev.ai/install.sh   # expect 302 → the release asset
```

`public/llms.txt` is a machine-readable product summary for AI agents (llmstxt.org).
