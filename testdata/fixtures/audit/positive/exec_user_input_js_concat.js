const child_process = require("child_process");

// String-concatenation command building — the "literal" + userVar form.
function runListing(req) {
  child_process.exec("ls " + req.query.dir);
}

function runCat(req) {
  // bare (destructured-import) exec with concatenation
  exec("cat " + req.query.file);
}
