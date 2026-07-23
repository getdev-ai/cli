// PREC-05: Drizzle's `sql` tagged template is a PARAMETERIZED construct, not
// raw string interpolation — the driver binds the interpolated values as
// parameters. This must NOT fire audit/sql-string-concat.
import { sql } from "drizzle-orm";

declare const db: { execute: (q: unknown) => Promise<unknown> };

export async function findUser(id: number) {
  return db.execute(sql`SELECT * FROM users WHERE id = ${id}`);
}
