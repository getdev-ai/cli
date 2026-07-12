// W3: child_process.exec(<identifier>) in TypeScript — the TS mirror
// previously had no positive fixture.
import child_process from "child_process";

export function runCommand(cmd: string): void {
  child_process.exec(cmd);
}
