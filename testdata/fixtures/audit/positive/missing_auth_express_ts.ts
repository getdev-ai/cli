// W3: an Express route with a single handler arg in TypeScript — the TS
// express-route mirror previously had no positive fixture.
import express from "express";

const app = express();

function getAdmin(req: express.Request, res: express.Response): void {
  res.json({ secret: "admin data" });
}

app.get("/admin", getAdmin);

export default app;
