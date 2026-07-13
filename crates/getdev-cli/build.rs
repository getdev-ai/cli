//! Re-exports Cargo's build-time `TARGET` triple as `GETDEV_TARGET` so the
//! self-update engine (`src/update/`) can resolve the release asset that
//! matches the *running* binary's platform (cargo-dist names assets
//! `getdev-<target>.tar.xz` / `.zip`). `TARGET` is only visible to build
//! scripts, not to the crate itself, so this bridge is the standard way to
//! make the exact triple available via `env!("GETDEV_TARGET")` at compile time.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| String::new());
    println!("cargo:rustc-env=GETDEV_TARGET={target}");
    // Only the target triple influences this script's output; don't rerun on
    // unrelated source changes.
    println!("cargo:rerun-if-changed=build.rs");
}
