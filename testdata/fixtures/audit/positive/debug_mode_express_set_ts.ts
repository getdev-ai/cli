// W3: the TS Express app.set("env", "development") form previously had no
// positive fixture.
import express from "express";

const app = express();
app.set("env", "development");

export default app;
