/**
 * Minimal Next.js config for the ship fixture. `output: "standalone"` is the
 * mode the generated Dockerfile depends on — it emits `.next/standalone`
 * (including `server.js`) which the runtime stage copies and runs with
 * `node server.js`.
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  output: "standalone",
};

module.exports = nextConfig;
