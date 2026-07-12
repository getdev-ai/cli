const child_process = require("child_process");

function runCommandSync(cmd) {
  return child_process.execSync(cmd);
}
