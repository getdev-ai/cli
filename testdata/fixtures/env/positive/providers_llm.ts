// seeded defects: additional Anthropic/OpenAI key shapes (values are fake)
// covers anthropic-api-key (2 more, on top of llm_client.ts) and
// openai-api-key (3) — CLAUDE.md hard rule 3 fixture backfill.
// Regression note (C4): sk-ant-… also matches the openai regex, so this
// file exercises both shapes to keep first-match-wins honest end to end.

export const anthropicKeyBackup = "sk-ant-FAKEFAKEFAKEFAKEFAKEFAA1";
export const anthropicKeyRotated = "sk-ant-FAKEFAKEFAKEFAKEFAKEFAB2";

export const openaiKeyA = "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAA1";
export const openaiKeyProject = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAB2";
export const openaiKeyC = "sk-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAC3";
