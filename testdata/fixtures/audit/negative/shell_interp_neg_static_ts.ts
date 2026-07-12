import * as child_process from "child_process";

function listDir(): void {
  child_process.exec("ls -la");
}
