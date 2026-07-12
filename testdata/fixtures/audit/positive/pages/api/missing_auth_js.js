// W3: a Next.js Pages Router handler in .js — the JS pages-handler mirror
// previously had no positive fixture.
export default function handler(req, res) {
  void req;
  res.status(200).json({ secret: "admin data" });
}
