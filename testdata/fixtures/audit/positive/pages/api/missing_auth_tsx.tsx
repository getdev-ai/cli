// W2: a Next.js Pages Router API handler authored as .tsx under pages/api —
// same false-negative as the App Router case before `tsx` joined the rule's
// `languages` list.
export default function handler(req: unknown, res: { json: (b: unknown) => void }) {
  void req;
  res.json({ secret: "admin data" });
}
