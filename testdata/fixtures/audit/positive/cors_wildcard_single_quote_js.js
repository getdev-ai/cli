const express = require("express");
const cors = require("cors");

const app = express();
// Single-quoted wildcard — the common JS style the double-quote-only
// #eq? predicate used to miss (IN-03).
app.use(cors({ origin: '*' }));

module.exports = app;
