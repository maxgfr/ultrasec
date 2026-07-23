# Severity & discipline (keep the report honest)

The engine narrows the repo and proves the boring half mechanically; **the severity
call and the false-positive call are yours.** A short report with 3 real findings is
worth more than a long one with 30 theoretical ones. This is the discipline that keeps
ultrasec's output trusted.

## Only report what you can exploit

Every finding needs a concrete attacker scenario: **who** is the attacker, **what** do
they send, **what** do they get? "An attacker could theoretically…" is not a finding;
"send this request, get this result" is. If you need the words *potentially* or
*theoretically*, you haven't finished the work — keep reading the code, or leave it
`needs-human`. This is the same bar as a `supported` verify verdict's `exploitPath`.

## Defense-in-depth gaps are hardening notes, not findings

If Layer A already prevents the attack, the absence of Layer B is a **hardening note**,
not a vulnerability — it gets no severity. Report it in the report's hardening-notes
section (the `hardeningNotes` narrative field), never inflated into a finding. "Missing
a second validation where the query builder already parameterizes" is hardening, not
HIGH.

## Calibrate against a baseline (do this in `context`)

When you author `CONTEXT.md`, name a **comparable mainstream application** and calibrate
against it — don't dismiss findings, focus effort:

- Same pattern, and it's been **exploited** in the comparable ⇒ a **stronger** finding.
- Same pattern, **never** exploited there in years of production ⇒ understand *why*
  before you report it (there's usually a mitigation you haven't found yet).

Don't hard-code one comparable: a CMS is judged against other CMSes, an API gateway
against other gateways. A genuinely novel app may have no meaningful comparable — say so.

## Recon before you hunt (the `context` questions)

`context` emits a deterministic scaffold; turn it into a `CONTEXT.md` that answers:

1. **What is this & what's the baseline?** App type (web app, API, CLI, library, daemon),
   who uses it and how, the stack, and the comparable mainstream app + the tradeoffs that
   comparable accepts.
2. **Trust boundaries & access control.** Where does untrusted input enter? How do callers
   prove identity (sessions, tokens, API keys, mTLS)? How is authorization enforced
   (middleware, decorators, capability checks)? Does it run as root / drop privileges /
   sandbox? Any bypass modes (dev/test/setup/debug)?
3. **Input-surface inventory.** Every network surface (routes, gRPC, WS, listeners), file
   input (uploads, config, import/export), IPC/CLI/env, user-generated content stored then
   rendered, and external integrations (OAuth, webhooks, plugins, dynamic code).

Understand the **trust model** first — if the design says admins are fully trusted, an
admin doing admin things is not a finding.

## Severity rubric (likelihood × impact)

Severity is likelihood (how easy, what access is needed) **and** impact (what damage).
If you can't describe the concrete damage, the severity is lower than you think.

- **CRITICAL** — unauthenticated RCE, full DB dump, admin takeover without credentials.
- **HIGH** — authenticated RCE, SQLi with data exfiltration, stored XSS firing for all
  users, auth bypass. Also any finding where an **explicit security boundary is defeated**:
  a user performs an action the system gates behind a higher role, with real consequences.
- **MEDIUM** — targeted XSS needing specific conditions, CSRF with meaningful state change,
  disclosure of secrets/credentials. Also business-logic bypasses with real but limited
  blast radius (requires auth, or confined to the attacker's own data, or needs uncommon
  conditions).
- **LOW** — disclosure of non-secret data, DoS needing sustained effort, hardening gaps.

**HIGH vs MEDIUM for business logic:** does it **defeat an explicit security boundary**?
A user doing what the system explicitly gates behind a higher role = HIGH. A data
inconsistency, or a bypass that itself requires privileged access, or limited blast
radius = MEDIUM.

> This rubric calibrates *your* judgement; it never overrides ultrasec's conservative
> gate. An uncertain high/critical finding stays **needs-human** — `verify`/`revalidate`
> never auto-dismiss it. Use the rubric to *rank and describe*, not to silently drop.

## Logging hygiene (opt-in `scan --log-hygiene`)

CWE-117 (log injection — untrusted data reaches a log call) and CWE-532 (sensitive
data written to a log) are **low/medium** severity by default: a forged log line or
a leaked credential in a log is real, but rarely the whole attack — rate it against
what actually reads that log (a SIEM parsing raw text vs. a structured logger) and
what the "sensitive" value turns out to be (a real secret vs. a variable *named*
`token` that never holds one). If a CRLF-stripping logger, a structured/JSON log
sink, or a redaction middleware already sits between the call and storage, treat the
absence of a *second* guard as a **hardening note**, not a finding. These checks are
**opt-in** (not part of the default `scan`) precisely because logging call sites are
numerous and easy to flood a report with — turn it on when logging hygiene is
actually in scope for the audit, and keep the same discipline as everywhere else:
report what you can show reaches an untrusted value, not every log statement.

## Anti-patterns (what makes an audit useless)

1. **Listing every OWASP deviation as a finding.** OWASP is a checklist, not a bug list.
2. **Rating defense-in-depth HIGH/CRITICAL.** A redundant guard's absence isn't HIGH.
3. **Ignoring the deployment model.** Rate-limiting at the CDN is a valid architecture;
   not every app needs app-level rate limiting.
4. **Treating designed behavior as a bug.** Learn the trust model first.
5. **Padding with LOWs to look thorough.** Ten LOWs don't beat three real MEDIUMs.
6. **"Potential" findings without proof.** Either you can exploit it or you can't.
7. **Ignoring what the codebase does well.** If auth is solid, say so — it calibrates
   trust in the findings you *do* report (the `positivePatterns` narrative field).
8. **Exploits built on unverified parser/runtime assumptions.** The most convincing false
   positives reason "the parser will treat this as…" without checking. Cite the spec or
   test it.
9. **Skipping business logic & creative attacks.** Scanners already check SQLi/XSS/SSRF;
   the value of a manual pass is the logic errors they can't — see
   [hunting-heuristics.md](hunting-heuristics.md).
10. **Giving up too early.** "It uses parameterized queries, so no SQLi" is lazy — check
    every `raw()`, every dynamic identifier, search/FTS, and any path that bypasses the
    builder. Push before concluding "nothing here."

## Reporting completeness

The rendered report (via `narrative` → `render --narrative`) should carry, beyond the
findings:

- **`positivePatterns`** — what the codebase does well (solid auth, parameterized
  queries, good secret hygiene). Honest praise calibrates trust and helps the team
  prioritise the real findings.
- **`hardeningNotes`** — defense-in-depth suggestions, explicitly **not** findings and
  kept out of the severity counts.

Both are advisory prose: they cite no finding ids and are never grounding-dropped, but
they also never change a finding's status. An honest "no exploitable vulnerabilities
found" is a valid result — but push hard (anti-pattern 10) before you reach it.

## Coverage improves with more runs

One pass explores only part of the surface — which paths get read depends on where you
dig. Re-run and fold passes into one dossier with `--merge` (verdicts preserved). When
re-auditing, weight effort toward the classes and regions earlier passes under-covered
(if the last run hammered injection, lean this one toward authz, business logic, and the
wildcard pass). On a first/only pass, say so in the report and recommend another.
