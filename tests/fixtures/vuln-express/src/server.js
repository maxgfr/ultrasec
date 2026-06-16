const express = require("express");
const { getUser } = require("./db");
const { runReport } = require("./report");

const app = express();

// VULN (SQLi, CWE-89): req.query.id is untrusted and flows across files into a
// string-concatenated SQL query in db.getUser without sanitization.
app.get("/user", (req, res) => {
  const id = req.query.id;
  const row = getUser(id);
  res.json(row);
});

// VULN (command injection, CWE-78): req.query.name flows into report.runReport
// which builds a shell command.
app.get("/report", (req, res) => {
  const name = req.query.name;
  const out = runReport(name);
  res.send(out);
});

app.listen(3000);
