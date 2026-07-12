// W2: child_process.exec built from an interpolated template literal,
// exercised from a .tsx module.
import * as child_process from "child_process";

export function Lister({ dir }: { dir: string }): JSX.Element {
  child_process.exec(`ls ${dir}`);
  return <div>{dir}</div>;
}
