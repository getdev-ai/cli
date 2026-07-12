const child_process = require("child_process");

function listDir() {
  child_process.exec("ls -la");
}
