# Security audit — summary

repo `examples/vuln-express` · ultrasec 0.0.0-development  
findings: **3** — 🟥 CRITICAL 1 · 🟧 HIGH 1 · 🟨 MEDIUM 1 · 🟩 LOW 0 · ⬜ INFO 0  
tools: none (graph + taint only)

## Confirmed (2)
- 🟥 CRITICAL **OS command injection: untrusted input reaches execSync()** — `src/server.js:18` → `src/server.js:19` → `src/report.js:5` (CWE-78)
- 🟧 HIGH **SQL injection: untrusted input reaches query()** — `src/server.js:10` → `src/server.js:11` → `src/db.js:6` (CWE-89)

