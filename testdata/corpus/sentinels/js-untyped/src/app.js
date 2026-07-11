// A3 regression sentinel: `acme-metrics` is genuinely installed
// (node_modules/acme-metrics/ exists) but ships no `.d.ts`/`types` field —
// the "installed but untyped" path. A member usage against it must resolve
// to `SurfaceTier::Unreadable` and stay info-severity (never high) — the
// package genuinely exists and is genuinely used; getdev just cannot read
// its surface statically.
import { track } from 'acme-metrics';

track('page_view');
