function formatUser(user) {
  const name = user.name || "anon";
  // TODO: support display names from the profile service
  console.log("formatUser called", user);
  return "user:" + name;
}

module.exports = { formatUser };
