function getUser(db: { query: (sql: string) => unknown }, userId: string): unknown {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}
