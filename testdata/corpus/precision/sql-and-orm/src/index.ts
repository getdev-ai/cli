declare const db: { query: (q: string) => unknown; execute: (q: unknown) => unknown };

// a local `sql` tag — a parameterized ORM template, no external import
function sql(strings: TemplateStringsArray, ...values: unknown[]) {
  return { strings, values };
}

// genuine raw ${} interpolation into .query(...) — should fire (medium)
export function rawQuery(id: number) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

// parameterized Drizzle-style sql`` tagged template — should NOT fire
export function safeQuery(id: number) {
  return db.execute(sql`SELECT * FROM users WHERE id = ${id}`);
}

rawQuery(1);
safeQuery(2);
