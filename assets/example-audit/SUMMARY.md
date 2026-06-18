# Security audit — summary

repo `examples/vuln-express` · ultrasec 0.0.0-development  
findings: **3** — 🟥 CRITICAL 1 · 🟧 HIGH 1 · 🟨 MEDIUM 1 · 🟩 LOW 0 · ⬜ INFO 0  
tools: none (graph + taint only)  
_ranked by composite risk (severity ⊕ EPSS ⊕ KEV)_

## Executive summary (AI-authored)
_AI-authored — verify against the cited findings before acting._

Two confirmed injection vulnerabilities in a public Express API: untrusted req.query values reach a raw SQL query and a shell command across files, with no validation. Both are directly exploitable by any client.

## Confirmed (3)
- 🟥 CRITICAL **OS command injection: untrusted input reaches execSync()** — `src/server.js:18` → `src/server.js:19` → `src/report.js:5` (CWE-78) · risk 60
- 🟧 HIGH **SQL injection: untrusted input reaches query()** — `src/server.js:10` → `src/server.js:11` → `src/db.js:6` (CWE-89) · risk 48
- 🟨 MEDIUM **Cross-site scripting (reflected): untrusted input reaches send()** — `src/server.js:18` → `src/server.js:20` (CWE-79) · risk 30

