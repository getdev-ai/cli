export { pad } from "left-pad";

async function load() {
  const mod = await import("totally-fake-dynamic-only-pkg");
  return mod;
}

load();
