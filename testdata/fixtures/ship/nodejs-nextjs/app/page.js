// Trivial home route so the standalone build has a page to render at `/`
// (the generated Dockerfile's HEALTHCHECK probes `/`).
export default function Home() {
  return <main>ship-fixture-nextjs ok</main>;
}
