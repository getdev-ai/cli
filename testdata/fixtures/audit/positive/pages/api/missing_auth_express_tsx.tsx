// Express-style route registration written in a .tsx module — exercises the
// tsx mirror of the Express `app.get(path, handler)` missing-auth matcher
// (the systematic tsx mirror added by WR-03/991be56). Scanned because it
// lives under pages/api/** (missing-auth's path_glob admits .tsx there).
import express from "express";

const app = express();
app.get("/widgets", getWidgets);

export default app;
