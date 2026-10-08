# Security audit report

`examples/vuln-express` · ultrasec 0.0.0-development · 4 candidate(s) · citations resolve

**Status:** ✅ adjudicated & grounded — 2 confirmed · 1 needs human · 0 undecided · 1 dismissed

**Contents:** [1. Executive summary](#1-executive-summary) · [2. Dashboard](#2-dashboard) · [3. Attack chains](#3-attack-chains) · [4. Follow-up vs previous audit](#4-follow-up-vs-previous-audit) · [5. Detailed findings](#5-detailed-findings) · [6. Secrets & history](#6-secrets--history) · [7. CI/CD & infrastructure exposure](#7-cicd--infrastructure-exposure) · [8. Dependencies](#8-dependencies) · [9. Hardening notes](#9-hardening-notes) · [10. Coverage & limits](#10-coverage--limits) · [11. Remediation plan](#11-remediation-plan) · [Annex A — Dismissed candidates](#annex-a--dismissed-candidates) · [Annex B — Needs human review](#annex-b--needs-human-review) · [Annex C — Engines & usage](#annex-c--engines--usage)

## 1. Executive summary

_AI-authored — verify against the cited findings before acting._

Two confirmed injection flaws in a public Express API. Untrusted req.query values cross file boundaries into a raw SQL statement and a shell command, with no validation on any hop and no authentication on either route, so both are exploitable by any unauthenticated client — command injection first, which yields code execution as the app user. Both come from the same habit: request values handed straight to a helper that builds an interpreter string.

**2 confirmed** (1 critical, 1 high), **1 awaiting a human decision**, out of 4 candidates.

Most urgent:

- 🟥 CRITICAL OS command injection: untrusted input reaches execSync() — src (`3ffa0917b004`)
- 🟧 HIGH SQL injection: untrusted input reaches query() — src (`54b733703450`)

## 2. Dashboard

| severity | confirmed | needs human | undecided | dismissed | total |
|---|---|---|---|---|---|
| 🟥 CRITICAL | 1 | 0 | 0 | 0 | 1 |
| 🟧 HIGH | 1 | 0 | 0 | 0 | 1 |
| 🟨 MEDIUM | 0 | 0 | 0 | 1 | 1 |
| 🟩 LOW | 0 | 1 | 0 | 0 | 1 |
| ⬜ INFO | 0 | 0 | 0 | 0 | 0 |

| surface | confirmed | needs human | undecided | dismissed |
|---|---|---|---|---|
| source code | 2 | 0 | 0 | 1 |
| secrets | 0 | 0 | 0 | 0 |
| CI/CD & infra | 0 | 1 | 0 | 0 |
| dependencies | 0 | 0 | 0 | 0 |

By area (live candidates; areas are detected workspaces, else the first two path segments):

| area | critical | high | medium | low/info | of which decided | undecided |
|---|---|---|---|---|---|---|
| `src` | 1 | 1 | 0 | 1 | 3 | 0 |

## 3. Attack chains

_AI-authored — verify against the cited findings before acting._

### Unauthenticated code execution, then data access

Steps: OS command injection: untrusted input reaches execSync() (`3ffa0917b004`) → SQL injection: untrusted input reaches query() (`54b733703450`)

Neither route requires authentication. GET /report gives shell execution as the app user (report.js:5), which already reaches the database file directly; GET /user independently returns arbitrary rows (db.js:6). Fixing only the SQL injection leaves the stronger path intact.

## 4. Follow-up vs previous audit

| outcome | count | examples |
|---|---|---|
| ✅ fixed | 0 | — |
| ⏳ still present | 2 | OS command injection: untrusted input reaches execSync() (`3ffa0917b004`), SQL injection: untrusted input reaches query() (`54b733703450`) |
| ❓ escalated / uncertain | 0 | — |
| 🆕 new since (not revalidated) | 1 | Web misconfig — No security-headers middleware where the app is built (`698ed561f7dd`) |

_Per-finding table: `render --full` (annex D)._

## 5. Detailed findings

Confirmed and needs-human findings in this repository's own code, by severity then area. A repeated finding is one card.

### 5.1 Critical (1)

#### Area `src`

##### 🟥 CRITICAL OS command injection: untrusted input reaches execSync()

`3ffa0917b004` · area `src` · CWE-78 · OWASP A03 Injection · priority **P0** · effort — · confirmed (supported) · found by ultrasec

- **Where:** `src/server.js:18` → `src/server.js:19` → `src/report.js:5`
- **Attacker scenario:** GET /report?name=x;sleep%205 · unauthenticated → the response takes 5s (baseline ~40ms), proving shell execution as the app user
- **Fix:** Replace execSync with execFile and an argv array: execFile("generate-report", ["--for", name]). An argv array removes the shell, but it does not stop argument injection — validate `name` against an allow-list (or pass it after a `--` terminator) so it can't be read as an option. · owner @backend

```diff
- return execSync("generate-report --for " + name).toString();
+ return execFileSync("generate-report", ["--for", "--", name]).toString();
```

- **Notes:** Verdict (supported): req.query.name is concatenated into a shell string at report.js:5 and executed with execSync; no validation on any hop, and the route has no auth. · Revalidation (still-valid): report.js:5 is unchanged at HEAD — still execSync on a concatenated string. · risk 60
- **Evidence:** Cross-file candidate: http input at src/server.js:18 may reach the command sink execSync() at src/report.js:5 through 2 hop(s). Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell. Heuristic — verify the data ac…

### 5.2 High (1)

#### Area `src`

##### 🟧 HIGH SQL injection: untrusted input reaches query()

`54b733703450` · area `src` · CWE-89 · OWASP A03 Injection · priority **P1** · effort — · confirmed (supported) · found by ultrasec

- **Where:** `src/server.js:10` → `src/server.js:11` → `src/db.js:6`
- **Attacker scenario:** GET /user?id=1%20OR%201=1 · unauthenticated → returns every row of `users`, proving the value is parsed as SQL, not data
- **Fix:** Bind the value instead of concatenating it, exactly as getUserSafe already does: sqlite.query("SELECT * FROM users WHERE id = ?", [id]). · owner @backend

```diff
- const sql = "SELECT * FROM users WHERE id = " + id;
- return sqlite.query(sql);
+ return sqlite.query("SELECT * FROM users WHERE id = ?", [id]);
```

- **Notes:** Verdict (supported): req.query.id is concatenated into SQL at db.js:5 and reaches sqlite.query() with no parameter array. The parameterized sibling getUserSafe (db.js:11) is NOT on this path. · Revalidation (still-valid): db.js:6 is unchanged at HEAD, and the concatenation it consumes is still at db.js:5. · risk 48
- **Evidence:** Cross-file candidate: http input at src/server.js:10 may reach the sql sink query() at src/db.js:6 through 2 hop(s). Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query. Heuristic — verify the data actually reaches the sink unsanitized before trusting it.

## 6. Secrets & history

_No live secret finding._

## 7. CI/CD & infrastructure exposure

Workflows, infrastructure-as-code and security configuration — read as a diff, one row per class.

| priority | worst | class | verdicts | where |
|---|---|---|---|---|
| P2 | 🟩 LOW | Web misconfig — No security-headers middleware where the app is built | 1 needs-human | `src/server.js:5` |

##### 🟩 LOW Web misconfig — No security-headers middleware where the app is built

`698ed561f7dd` · area `src` · CWE-693 · OWASP A05 Security misconfiguration · priority **P2** · effort — · needs-human (partial) · found by ultrasec

- **Where:** `src/server.js:5`
- **Attacker scenario:** _not established — that is why it needs a human (see notes)._
- **Notes:** Verdict (partial): server.js:5 builds the Express app and registers no helmet()/security-headers middleware, so responses carry no CSP, HSTS or X-Frame-Options. Real, but a hardening gap rather than an exploit on its own: what it costs depends on whether a reverse proxy in front sets these headers, which the repo cannot show. · risk 15
- **Evidence:** The file constructs the application and registers no `helmet()` / `secureHeaders()` / equivalent. Without it the responses carry no CSP, HSTS, X-Frame-Options or X-Content-Type-Options. Register it first, before any route — unless a reverse proxy in front sets these headers, which is the thing to c…

## 8. Dependencies

_No live dependency advisory._

## 9. Hardening notes

_AI-authored — verify against the cited findings before acting. Defense in depth — **not** findings, excluded from every count._

**What the codebase does well:** The data layer already knows how to do this correctly — db.getUserSafe (src/db.js:11) uses a `?` placeholder with a parameter array, so the parameterized path exists and is the one to standardize on. The two findings below are deviations from it, not a missing capability.

- Neither route validates the shape of its input before use (an integer id, a report name from a known set). Type/shape validation at the boundary is defense in depth once the two fixes above land — it is not what makes them exploitable today.
- res.send() at server.js:20 returns command output with the default text/html content type. Once the command injection is fixed the attacker no longer controls that body, but setting an explicit content type (or res.json) removes the reflected-content question entirely.

## 10. Coverage & limits

**Not looked at / limits:**

- no external scanner ran — graph + taint only
- static analysis only: no DAST, no fuzzing, no authenticated crawling, no runtime testing

### Coverage (OWASP ASVS)

What this audit looked at, and what it did not. A category marked **not examined** is not
a clean bill of health — it is a gap in the audit, and it belongs in the report.

| | category | state | findings |
|---|---|---|---|
| V1 | Architecture & threat modelling | ⬜ **not examined** | — |
| V2 | Authentication | ⬜ **not examined** | — |
| V3 | Session management | ⬜ **not examined** | — |
| V4 | Access control | ⬜ **not examined** | — |
| V5 | Validation, sanitization & encoding | ✅ examined | 3 |
| V6 | Stored cryptography | ⬜ **not examined** | — |
| V7 | Error handling & logging | ⬜ **not examined** | — |
| V8 | Data protection & privacy | ⬜ **not examined** | — |
| V9 | Communications | ⬜ **not examined** | — |
| V11 | Business logic | ⬜ **not examined** | — |
| V12 | Files & resources | ⬜ **not examined** | — |
| V13 | API & web service | ⬜ **not examined** | — |
| V14 | Configuration & supply chain | ✅ examined | 1 |

#### Not examined (11)

- **V1 Architecture & threat modelling** — Did CONTEXT.md establish a trust model and a threat model, or was severity rated in the abstract?
- **V2 Authentication** — Password/OTP/session-establishment paths read? Credential comparison constant-time?
- **V3 Session management** — Token lifetime, rotation on privilege change, invalidation on logout.
- **V4 Access control** — The highest-yield class, and never enumerable: every route's guard vs. the object it returns (IDOR).
- **V6 Stored cryptography** — Weak-hash detection is mechanical; key management, IV reuse and constant-time comparison are not.
- **V7 Error handling & logging** — The error-HANDLING half is enumerated (CWE-209 — a caught error written into the response body). Needs `scan --log-hygiene` for the logging half (CWE-117/532).
- **V8 Data protection & privacy** — Where personal data goes, how long it stays, whether pseudonymisation is reversible.
- **V9 Communications** — TLS verification disabled anywhere? Certificate pinning claims that do not hold?
- **V11 Business logic** — Workflow skipping, price/quantity tampering, replay, quota bypass, races on balance. Anti-automation is partly enumerated: `scan` finds unbounded similarity/distance calls (CWE-407), `guards --lens throttle` finds handlers nothing rate-limits.
- **V12 Files & resources** — Traversal and zip-slip are enumerated; upload type/size/AV policy is not.
- **V13 API & web service** — SSRF and open redirect are enumerated; GraphQL field authz and mass-assignment on API models are not.

#### Answer these explicitly (9)

No deterministic signal can establish coverage here. For each, write either a finding or
one line saying **why it does not apply to this repo** — "not applicable" without a
reason is how coverage silently shrinks between audits.

- **V1 Architecture & threat modelling** — Did CONTEXT.md establish a trust model and a threat model, or was severity rated in the abstract?
- **V2 Authentication** — Password/OTP/session-establishment paths read? Credential comparison constant-time?
- **V3 Session management** — Token lifetime, rotation on privilege change, invalidation on logout.
- **V4 Access control** — The highest-yield class, and never enumerable: every route's guard vs. the object it returns (IDOR).
- **V6 Stored cryptography** — Weak-hash detection is mechanical; key management, IV reuse and constant-time comparison are not.
- **V8 Data protection & privacy** — Where personal data goes, how long it stays, whether pseudonymisation is reversible.
- **V9 Communications** — TLS verification disabled anywhere? Certificate pinning claims that do not hold?
- **V11 Business logic** — Workflow skipping, price/quantity tampering, replay, quota bypass, races on balance. Anti-automation is partly enumerated: `scan` finds unbounded similarity/distance calls (CWE-407), `guards --lens throttle` finds handlers nothing rate-limits.
- **V13 API & web service** — SSRF and open redirect are enumerated; GraphQL field authz and mass-assignment on API models are not.

#### Weakness classes × frameworks

Each detected framework against each weakness class: matched by a pack (`✅`), not applicable (`➖`),
handed to the AI hunt (`🔎` pending, `🧭` done), or **not covered**. A `⚠` cell is degraded — no framework
pack, or a version outside the range the pack was validated on — and is hunted, not trusted.

| class | express 4.17.1 |
|---|---|
| timing-unsafe-secret-compare | ✅ pack |
| csv-formula-injection | ✅ pack |
| client-ip-first-xff | ✅ pack |
| unbounded-public-export | ✅ pack |
| security-headers-absent | ✅ pack |
| session-cookie-chunks-on-logout | ⬜ **not covered** ⚠ |
| env-bool-coercion | ✅ pack |
| insecure-session-cookie | ✅ pack |
| proxy-headers-trusted | ✅ pack |
| request-body-unbounded | ✅ pack |
| graphql-introspection-enabled | ✅ pack |
| csrf-protection-disabled | ✅ pack |
| debug-mode-enabled | ✅ pack |
| taint-catalog | ✅ pack |

Degraded or uncovered (1): express — pack express has no idiom for this class.
Run `ultrasec investigate` — it emits one hunt per such cell.


## 11. Remediation plan

Root causes (AI-authored — verify against the cited findings before acting.) — fixing one closes every finding under it:

- **Request values handed to a helper that builds an interpreter string** (`3ffa0917b004`, `54b733703450`) — Both handlers read req.query.* and pass it, unvalidated, to a helper that concatenates it into SQL or a shell command. The fix is structural, not per-site: bind parameters at the data layer and use argv arrays for process execution, then add validation at the route boundary so a future helper inherits neither habit.

### P0 — fix now (1)

- [ ] **OS command injection: untrusted input reaches execSync()** · `src` · `3ffa0917b004` — Replace execSync with execFile and an argv array: execFile("generate-report", ["--for", name]). An argv array removes the shell, but it doe…

### P1 — this sprint (1)

- [ ] **SQL injection: untrusted input reaches query()** · `src` · `54b733703450` — Bind the value instead of concatenating it, exactly as getUserSafe already does: sqlite.query("SELECT * FROM users WHERE id = ?", [id]).

### P2 — planned (1)

- [ ] **Decide: Web misconfig — No security-headers middleware where the app is built** · `src` · `698ed561f7dd`

## Annex A — Dismissed candidates

1 candidate(s) dismissed — summarised. Every one keeps its id, ground and argument in `findings.json`; `render --full` lists them all.

| ground | count | meaning |
|---|---|---|
| **dismissed — no ground recorded** | 1 |  |

| produced by | count |
|---|---|
| ultrasec | 1 |

By shape:

| candidate shape | count | areas |
|---|---|---|
| Cross-site scripting (reflected): untrusted input reaches send() | 1 | `src` |

## Annex B — Needs human review

- 🟩 LOW Web misconfig — No security-headers middleware where the app is built — `src` — `src/server.js:5` `698ed561f7dd` — Verdict (partial): server.js:5 builds the Express app and registers no helmet()/security-headers middleware, so responses carry no CSP, HSTS or X-Frame-Options…

## Annex C — Engines & usage

- engine: ultrasec 0.0.0-development (schema 11) · extraction cache, AST
- languages: javascript
- stack: Express 4.17.1

External scanners: none — graph + taint only.

Run directory: `REPORT.md` · `REPORT.html` · `findings.json` · `manifest.json` · `CONTEXT.md` · `NARRATIVE.json`.

---

_Engine: ultrasec 0.0.0-development. Taint candidates are deterministic; external-tool results depend on installed scanners. Every finding keeps its own id in `findings.json`; this report groups and summarises, it never merges or decides. Exhaustive annexes: `ultrasec render --full`._
