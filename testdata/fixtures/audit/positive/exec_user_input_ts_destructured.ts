// W3: bare exec(<identifier>) (destructured import) in TypeScript.
import { exec } from "child_process";

export function runCommand(cmd: string): void {
  exec(cmd);
}
