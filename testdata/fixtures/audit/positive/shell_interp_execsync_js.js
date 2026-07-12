const child_process = require("child_process");

function removeTarget(target) {
  return child_process.execSync(`rm -rf ${target}`);
}
