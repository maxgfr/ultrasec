const express = require("express");
const { lookupUser } = require("./service");
const { buildReport } = require("./report");
const { readDoc } = require("./files");
const { fetchUrl } = require("./fetcher");

const app = express();

// VULN (SQLi, CWE-89): req.query.id flows routes.js -> service.js -> db.js — a
// call chain crossing THREE files before hitting the raw SQL sink.
app.get("/user", (req, res) => {
  const id = req.query.id;
  const row = lookupUser(id);
  res.json(row);
});

// VULN (command injection, CWE-78): req.query.name reaches execSync in report.js.
app.get("/report", (req, res) => {
  const name = req.query.name;
  res.send(buildReport(name));
});

// VULN (path traversal, CWE-22): req.query.doc reaches readFileSync in files.js.
app.get("/doc", (req, res) => {
  const doc = req.query.doc;
  res.send(readDoc(doc));
});

// VULN (SSRF, CWE-918): req.query.url reaches axios.get in fetcher.js — the
// receiver-gated member-call sink (a bare `get()` must NOT match).
app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  res.send(await fetchUrl(url));
});

app.listen(3000);
