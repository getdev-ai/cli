// W3: the TS explicit `secure: false` cookie form previously had no
// positive fixture.
import type { Request, Response } from "express";

export function login(req: Request, res: Response): void {
  const token = issueSessionToken(req.user);
  res.cookie("session", token, { secure: false });
  res.json({ ok: true });
}
