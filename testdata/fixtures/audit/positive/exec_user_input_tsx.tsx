// W2: both JS/TS shell-exec shapes (child_process.exec and the bare
// destructured exec) with a non-literal command, exercised from a .tsx file.
import child_process, { exec } from "child_process";

export function Runner({ cmd }: { cmd: string }): JSX.Element {
  child_process.exec(cmd);
  exec(cmd);
  return <div>running</div>;
}
