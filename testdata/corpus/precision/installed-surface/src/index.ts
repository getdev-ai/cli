import { eq, and, sql, notARealDrizzleExport } from 'drizzle-like';

// eq/and/sql ARE on the real exports-map surface (dist/index.d.ts) — no
// finding. This is the precision half of PREC-03: real installed members
// enumerated from the `exports["."].types` entry never false-fire.
eq(1, 2);
and(true, false);
void sql;

// A genuinely nonexistent member on the SAME trusted, fully-`Resolved`
// exports-map surface must STILL fire High (recall preserved, D-07) — this is
// the recall anchor cataloged in getdev-precision.json. If the resolver ever
// regressed to `Dynamic` for exports-map packages, this High would silently
// disappear and the oracle's recall check would fail.
void notARealDrizzleExport;
