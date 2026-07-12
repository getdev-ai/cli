const express = require("express");

const app = express();

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

function getAdmin(req, res) {
  res.json({ secret: "admin data" });
}

app.get("/admin", requireAuth, getAdmin);

module.exports = app;
