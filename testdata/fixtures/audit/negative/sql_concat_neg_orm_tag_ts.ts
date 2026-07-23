// PREC-05: a `sql`-tagged template passed to `.query(...)` — still the
// parameterized ORM-tag shape, not raw interpolation. Must not fire.
import { sql } from "drizzle-orm";

declare const db: { query: (q: unknown) => Promise<unknown> };

export async function countByStatus(status: string) {
  return db.query(sql`SELECT count(*) FROM orders WHERE status = ${status}`);
}
