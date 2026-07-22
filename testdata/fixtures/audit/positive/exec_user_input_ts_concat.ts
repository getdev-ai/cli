import child_process from "child_process";

function runListing(req: { query: { dir: string } }): void {
  child_process.exec("ls " + req.query.dir);
}

function runCat(req: { query: { file: string } }): void {
  exec("cat " + req.query.file);
}
