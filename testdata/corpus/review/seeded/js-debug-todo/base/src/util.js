function formatUser(user) {
  const name = user.name || "anon";
  return "user:" + name;
}

module.exports = { formatUser };
