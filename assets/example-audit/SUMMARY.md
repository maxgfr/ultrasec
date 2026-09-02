# Security audit — summary

repo `examples/vuln-express` · ultrasec 0.0.0-development  
findings: **4** — 🟥 CRITICAL 1 · 🟧 HIGH 1 · 🟨 MEDIUM 1 · 🟩 LOW 1 · ⬜ INFO 0  
tools: none (graph + taint only)  
_ranked by composite risk (severity ⊕ EPSS ⊕ KEV)_

## Executive summary (AI-authored)
_AI-authored — verify against the cited findings before acting._

Two confirmed injection flaws in a public Express API. Untrusted req.query values cross file boundaries into a raw SQL statement and a shell command, with no validation on any hop and no authentication on either route, so both are exploitable by any unauthenticated client — command injection first, which yields code execution as the app user. Both come from the same habit: request values handed straight to a helper that builds an interpreter string.

## What the codebase does well (AI-authored)
_AI-authored — verify against the cited findings before acting._

The data layer already knows how to do this correctly — db.getUserSafe (src/db.js:11) uses a `?` placeholder with a parameter array, so the parameterized path exists and is the one to standardize on. The two findings below are deviations from it, not a missing capability.

## Confirmed (2)
- 🟥 CRITICAL **OS command injection: untrusted input reaches execSync()** — `src/server.js:18` → `src/server.js:19` → `src/report.js:5` (CWE-78) · risk 60
- 🟧 HIGH **SQL injection: untrusted input reaches query()** — `src/server.js:10` → `src/server.js:11` → `src/db.js:6` (CWE-89) · risk 48

## Needs human review (1)
- 🟩 LOW Web misconfig — No security-headers middleware where the app is built — `src/server.js:5` (CWE-693) · risk 15

## Coverage caveat

**11 of 13** categories were NOT examined: Architecture & threat modelling · Authentication · Session management · Access control · Stored cryptography · Error handling & logging · Data protection & privacy · Communications · Business logic · Files & resources · API & web service.

This is a gap in the audit, not a clean bill of health. Full matrix in REPORT.md.
