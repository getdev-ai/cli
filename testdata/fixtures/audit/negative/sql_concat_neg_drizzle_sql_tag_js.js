// PREC-05: the same parameterized Drizzle `sql` tagged template in JS — the
// tag parameterizes the interpolation, so this is safe and must not fire.
const { sql } = require("drizzle-orm");

async function findUser(db, id) {
  return db.execute(sql`SELECT * FROM users WHERE id = ${id}`);
}

module.exports = { findUser };
