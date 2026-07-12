function fetchCookieRecipe(db) {
  return db.query("SELECT * FROM cookie_recipes");
}

module.exports = fetchCookieRecipe;
