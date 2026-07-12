// W2: a .tsx server action setting a cookie with no Secure/HttpOnly opts and
// an explicit secure: false — both insecure-cookie shapes in one file.
import type { Request, Response } from "express";

export function setSession(req: Request, res: Response): JSX.Element {
  res.cookie("session", issueToken(req.user));
  res.cookie("refresh", issueRefresh(req.user), { secure: false });
  return <span>ok</span>;
}
