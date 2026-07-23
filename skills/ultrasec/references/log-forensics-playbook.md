# Log-forensics playbook (`ultrasec logs`)

`logs` is the **blue-team** sibling of `scan`: instead of hunting for bugs in
source code, it ingests log files you already have (nginx/access logs,
JSON-lines app logs, generic-timestamped text, raw) and runs deterministic
attack-signature detection over them — SQLi, XSS, path traversal, command
injection, sensitive-path probes, and known scanner/attack-tool user-agents.
Findings land in their **own dossier** (never the code-scan pipeline) and cite
`[logfile:line]` exactly like a source-code finding cites `[file:line]` — so
the same grounding gate (`check`), `verify`, and `render` you already use work
**unchanged**.

## 1. What the engine emits — candidates, not verdicts

Every signature hit is a deterministic regex match against one log line —
**recall-oriented and conservative at once**: the regex families are kept
tight (word-boundaried SQLi, literal sensitive-path segments, `;`/`&&`-gated
command chains) to keep the false-positive rate down, but a hit is still only
ever a *candidate*. The engine cannot tell a real attacker from a security
scanner your own team runs, a penetration test, or a coincidental string in a
legitimate request. **You judge every finding** the same way you'd judge a
taint candidate from `scan` — read the evidence, corroborate with context,
decide.

## 2. Emit and read

```
node scripts/ultrasec.mjs logs <path…> [--out .ultrasec-logs] [--budget quick|standard|thorough]
```

- `<path…>` — one or more log files and/or directories (directories expand to
  the `*.log`/`*.jsonl`/`*.txt`/text-looking files directly inside them).
- Writes a **standard dossier** (`manifest.json`, `findings.json`, `graph.json`
  — intentionally empty, `DOSSIER.md`) at `--out` (default `.ultrasec-logs`),
  plus **`LOGSTATS.json`**: per-file line counts/formats, top IPs, top request
  paths, HTTP status distribution, and the run's first/last timestamps —
  read this for the traffic context a single finding can't show you.
- Evidence in every finding message is **redacted by default** (secrets/PII —
  AWS keys, JWTs, `Authorization:` headers, query-string passwords/tokens,
  emails, Luhn-valid card numbers — become `‹REDACTED:<kind>›`). Pass
  `--no-redact` only in a trusted, throwaway environment.
- Start with `<out>/DOSSIER.md`, then drill into individual lines from the
  original file when you need full context (`sed -n '<line>,<line+5>p' <file>`).

## 3. Triage discipline, per family

- **`scanner-ua`** (a known scanner/attack-tool user-agent) **+ mostly 404s** —
  likely a mass internet scanner, not a targeted attack. Still worth a scan of
  `LOGSTATS.json`'s top IPs/paths for that source before dismissing.
- **`probe-path`/`traversal` that 404'd** — the probe failed; usually noise,
  but note it (a *pattern* of many distinct probes from one IP is a recon
  signal even if each individual hit is harmless).
- **`probe-path`/`traversal` that got a 2xx** (the engine already escalated
  the severity one notch and appended `(succeeded — 2xx)` to the message) —
  **investigate.** The request for a sensitive path or `../` sequence *worked*.
  Read the actual response if you still have it; confirm what was disclosed.
- **`sqli`/`xss`/`cmdinj`** — corroborate with `LOGSTATS.json`: is this IP a
  one-off, or does it show up across many distinct paths/times (a scripted
  sweep)? A single isolated hit from a normal browser UA is more likely a WAF
  test or a false positive than a real campaign; many hits from one source
  across many endpoints is a real attacker.
- Cross-reference `sink.kind` (the family) and the finding's evidence against
  `topIps`/`topPaths`/`statusCounts` before calling anything — the engine
  doesn't correlate across lines for you (yet — see §6).

## 4. Timeline reconstruction

For anything you decide is worth writing up:

1. Group every finding (and every benign request you check by hand) by **IP**.
2. Order by **line number** (or `ts` when the format has one — nginx dates
   aren't lexically sortable, so prefer line order within one file).
3. Write the narrative as a sequence of grounded steps, each citing
   `[logfile:line]` — e.g. "`nginx-combined.log:41` — sqlmap UA fingerprinting
   `/products?id=1`; `nginx-combined.log:42` — the same source attempts a
   UNION SELECT 3s later; `nginx-combined.log:58` — the same class of source
   probes `/.aws/credentials` and gets a 200." This is exactly the exploit-path
   discipline `scan` findings use — [citation-format.md](citation-format.md).

## 5. Escalation — indicators of compromise, never dropped

Some patterns are serious enough that an uncertain verdict must stay
**`needs-human`**, never `dismissed`:

- A successful authentication **after** a burst of failures from the same
  source (credential stuffing that worked).
- A real secret or token appearing **in the clear** in a log line (the engine
  already redacts evidence in the finding message — but if you're reading the
  raw file directly and see one, that's its own incident, independent of any
  signature hit).
- A traversal/probe-path hit that **succeeded** (2xx) against a genuinely
  sensitive target (`/etc/passwd`, `.env`, cloud credentials, `.git/config`).
- Any of the above corroborated across **multiple log sources** for the same
  actor (e.g. the same IP in an access log and an auth-failure burst in an
  app log).

Adjudicate exactly like any other finding: `verify` → a `supported`/`partial`
verdict with an `exploitPath`, or leave it `needs-human` if you can't rule
either way. **Never** `dismiss` a high/critical finding you can't positively
refute.

## 6. Scope — what this pass does NOT do (yet)

- **No behavioral aggregation.** Brute-force/burst detection (many failures
  from one IP in a short window) is a follow-up engine capability — for now,
  do that correlation yourself from `LOGSTATS.json` + the per-line findings.
- **No syslog format** (yet) — nginx/access, JSON-lines, generic-timestamped,
  and raw are supported today.
- **"Missing security logging"** as a *code-audit* finding (an endpoint with
  no audit trail at all) is judgment guidance for a `scan`/`investigate` pass
  over the **application source**, not something this engine detects from log
  content — there's nothing to detect in a log that was never written.

## 7. Verdicts via the normal flow

`logs` findings are ordinary findings — they flow through the same pipeline
as everything else:

```
node scripts/ultrasec.mjs verify --run .ultrasec-logs
# … fill VERIFY.json …
node scripts/ultrasec.mjs verify --apply VERIFY.json --run .ultrasec-logs
node scripts/ultrasec.mjs check --run .ultrasec-logs --semantic
node scripts/ultrasec.mjs render --run .ultrasec-logs
```

`revalidate` doesn't apply here (there's no git history for a log file), but
`triage`, `verify`, `check`, and `render` all work unmodified — see
[investigate-playbook.md](investigate-playbook.md) for the general shape of
"engine emits candidates, you judge, apply folds verdicts back in" if this is
your first time working an ultrasec worklist.
