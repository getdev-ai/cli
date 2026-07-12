const express = require("express");

const app = express();

function getAdmin(req, res) {
  res.json({ secret: "admin data" });
}

app.get("/admin", getAdmin);

module.exports = app;
