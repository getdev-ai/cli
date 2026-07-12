const child_process = require("child_process");

function listDir(dir) {
  child_process.exec(`ls ${dir}`);
}
