// object-literal key given as a STRING, not a bare identifier (A12,
// 03-REVIEW.md) — `{model: "x"}` was already extracted, `{"model": "x"}`
// was not
const config = { "model": "bogus-llm-9" };
