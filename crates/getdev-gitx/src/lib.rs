//! git interaction for getdev: snapshots under `refs/getdev/` and diff
//! extraction, by shelling out to the git binary (no git2/gix — settled
//! decision). Scaffold only — implemented in phases P4 (`snap`) and P5
//! (`review`).
