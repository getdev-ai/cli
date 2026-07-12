// W3: the TS template-literal interpolation SQL form previously had no
// positive fixture.
export function getUser(db: { execute: (sql: string) => unknown }, userId: string): unknown {
  return db.execute(`SELECT * FROM users WHERE id = ${userId}`);
}
