import { Request, Response } from "express";

export function login(req: Request, res: Response): void {
  const token = issueSessionToken(req.user);
  res.cookie("session", token, { secure: true, httpOnly: true });
  res.json({ ok: true });
}
