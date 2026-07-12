// server-side schema validation — an unrelated method name, must not fire
function handler(req, res) {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: "invalid" });
  }
}
