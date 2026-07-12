function login(req, res) {
  const token = issueSessionToken(req.user);
  res.cookie("session", token, { secure: false });
  res.json({ ok: true });
}

module.exports = login;
