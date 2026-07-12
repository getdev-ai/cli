function getUser(db, userId) {
  return db.execute(`SELECT * FROM users WHERE id = ${userId}`);
}
