const express = require("express");
const app = express();

// Handler A reads untrusted input and does nothing dangerous with it.
app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.json({ hello: String(name).length });
});

// Handler B runs a shell command built from a CONSTANT. Nothing from handler A
// can reach it — the two closures share a file and nothing else. Before source
// scoping this pair was emitted as a plain candidate, indistinguishable from a
// real flow.
app.get("/status", (_req, res) => {
  const { execSync } = require("child_process");
  res.send(execSync("uptime").toString());
});

// Handler C is the real thing: the source and the sink are in ONE closure.
app.get("/ping", (req, res) => {
  const host = req.query.host;
  const { execSync } = require("child_process");
  res.send(execSync("ping -c1 " + host).toString());
});

module.exports = app;
