import child_process from "child_process";

export function handler(req: { query: { dir: string; file: string } }) {
  child_process.exec("ls " + req.query.dir);
  exec("cat " + req.query.file);
  return null;
}
