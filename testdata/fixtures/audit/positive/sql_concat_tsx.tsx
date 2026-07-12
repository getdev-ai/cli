// W2: both JS/TS SQL-injection shapes (+ concatenation and template-literal
// interpolation) inside execute/query calls, exercised from a .tsx server
// component.
export async function UserRow({ db, userId }: {
  db: { query: (s: string) => Promise<unknown>; execute: (s: string) => Promise<unknown> };
  userId: string;
}): Promise<JSX.Element> {
  await db.query("SELECT * FROM users WHERE id = " + userId);
  await db.execute(`SELECT * FROM sessions WHERE user = ${userId}`);
  return <tr>{userId}</tr>;
}
