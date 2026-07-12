const child_process = require("child_process");

function runCommand(cmd) {
  child_process.exec(cmd);
}
