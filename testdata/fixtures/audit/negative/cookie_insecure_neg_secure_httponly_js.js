function login(req, res) {
  const token = issueSessionToken(req.user);
  res.cookie("session", token, { secure: true, httpOnly: true });
  res.json({ ok: true });
}

module.exports = login;
