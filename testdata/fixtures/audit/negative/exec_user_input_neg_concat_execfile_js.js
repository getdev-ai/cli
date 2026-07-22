const child_process = require("child_process");

// Concatenation, but passed to execFile (never invokes a shell) with the
// command and args as a separate array — must NOT trip exec-user-input.
function safe(req) {
  child_process.execFile("ls", ["-la", "" + req.query.dir]);
}
