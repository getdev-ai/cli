import http from "http";
import { greet } from "./src/util.js";

const server = http.createServer((req, res) => {
  res.end(greet("world"));
});

server.listen(3000);
