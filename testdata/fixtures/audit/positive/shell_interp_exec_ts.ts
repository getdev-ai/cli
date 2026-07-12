import * as child_process from "child_process";

function listDir(dir: string): void {
  child_process.exec(`ls ${dir}`);
}
