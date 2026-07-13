const REGISTERED = ["getUserProfile", "listProducts"];

function ping(req, res) {
  res.json({ ok: true });
}

function getUserProfile(req, res) {
  res.json({ id: req.params.id });
}

function listProducts(req, res) {
  res.json({ items: [] });
}

module.exports = { ping, REGISTERED };
