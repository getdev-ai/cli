/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export — the site is fully static and deploys to Cloudflare Pages.
  // No server runtime; `next build` emits `out/`.
  output: 'export',
  // Cloudflare Pages serves each route as a directory index (e.g. /out/index.html).
  trailingSlash: true,
  images: { unoptimized: true },
}

export default nextConfig
