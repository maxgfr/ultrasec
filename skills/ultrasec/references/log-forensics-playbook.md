# Log-forensics playbook (`ultrasec logs`)

`logs` is the **blue-team** sibling of `scan`: instead of hunting for bugs in
source code, it ingests log files you already have (nginx/access logs,
JSON-lines app logs, syslog/auth.log, generic-timestamped text, raw) and runs
three detector layers over them, in one streaming pass:

1. **per-line attack signatures** — SQLi, XSS, path traversal, command
   injection, sensitive-path probes, and known scanner/attack-tool user-agents;
2. **per-line secret/PII-leak detection** — a secret or PII value appearing in
   the clear in a log line (see §3's `log-secret-*` family);
3. **per-IP behavioral aggregation** — brute-force auth attempts, a possible
   credential compromise, request bursts, and scan→hit recon patterns, each
   built from bounded sliding-window state over the whole file (see §3's
   behavioral families).

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
node scripts/ultrasec.mjs logs <path…> [--out .ultrasec-logs] [--budget quick|standard|thorough] [--window <sec>]
```

- `<path…>` — one or more log files and/or directories (directories expand to
  the `*.log`/`*.jsonl`/`*.txt`/text-looking files directly inside them).
- Writes a **standard dossier** (`manifest.json`, `findings.json`, `graph.json`
  — intentionally empty, `DOSSIER.md`) at `--out` (default `.ultrasec-logs`),
  plus **`LOGSTATS.json`**: per-file line counts/formats, top IPs, top request
  paths, HTTP status distribution, the run's first/last timestamps,
  `authFailures`/`authSuccessAfterFailure` (raw auth-outcome counts, not
  gated by any threshold), and `distinctIpsSeen`/`distinctIpsOverflowed` (the
  behavioral aggregator's bounded per-IP state — see §6) — read this for the
  traffic context a single finding can't show you.
- `--window <sec>` (default 60) — the sliding-window size the behavioral
  detectors (§3) use. Widen it to catch a slower/low-and-slow attacker;
  narrow it to tighten what counts as "one burst."
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
  `topIps`/`topPaths`/`statusCounts` before calling anything.

**Behavioral families** (`sink.kind`, cross-line — built from a bounded
per-IP sliding window; the exact thresholds are heuristics, tuned to be
conservative but still HEURISTICS — verify before reporting, exactly like any
other candidate):

- **`brute-force`** — ≥20 failed-auth events from one IP inside the window
  (default 60s; falls back to a 500-line proxy window on a source with no
  parseable timestamp — classic BSD syslog has no year, so `auth.log` almost
  always uses this fallback; the finding's message says so explicitly). Cites
  the first failing line. A real distributed/slow-and-low attack can stay
  under this per-IP threshold — cross-check `LOGSTATS.json`'s `authFailures`
  (a raw, non-thresholded count) if the per-finding picture looks too clean.
- **`credential-compromise`** — a successful auth for an IP that already had a
  qualifying brute-force run. **Always `confidence: "low"`, always
  needs-human** (see §5) — a successful login after failures is EVIDENCE, not
  proof; the legitimate user mistyping their password before getting it right
  produces the exact same signature.
- **`request-burst`** — >300 requests from one IP inside the window. A
  recon/DoS indicator, not an attack confirmation — a legitimate but
  misbehaving client (a retry storm, a broken integration) produces the same
  shape. It counts EVERY line carrying an IP, including syslog/auth lines — so
  a `brute-force` run on the same IP can also trip it; corroborate the two
  against each other instead of treating them as two separate incidents.
- **`scan-behavior`** — ≥15 404/403 responses from one IP inside the window
  (directory/endpoint enumeration).
- **`recon-hit`** — the SAME IP, after qualifying as `scan-behavior`, later
  gets a 2xx on a sensitive path (the same probe-path signature family as
  §3's `probe-path`). This is the strongest of the behavioral findings —
  recon that found something — investigate what was disclosed.

**`log-secret-<kind>`** (e.g. `log-secret-aws-access-key`,
`log-secret-jwt`, `log-secret-email`) — a secret or PII value appearing in the
clear in a log line: `CWE-532`, capped at 25 per file. Secrets (AWS keys,
private keys, JWTs, query-string tokens, `Authorization:` headers, Slack/Google
API keys) are **high** severity; PII (Luhn-valid card numbers, and emails —
only once a file has ≥5 DISTINCT addresses, a bulk-leak heuristic that ignores
one-off appearances) is **medium**. The finding message is redacted by
default, same as every other family — but the underlying secret is REAL and
live on disk. **Rotate/invalidate every credential a `log-secret-*` finding
points at** (this is defensive guidance for YOU to relay, not something
ultrasec does): treat it the same way you'd treat a `gitleaks`/`kingfisher`
hit from `scan` — assume compromise, rotate the credential at its source
(AWS/IAM console, the app's secret store, …), then confirm the log itself gets
scrubbed or access-restricted so the plaintext doesn't linger.

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

- A `credential-compromise` finding (§3) — a successful authentication
  **after** a qualifying burst of failures from the same source. The engine
  now surfaces this automatically (`confidence: "low"` by construction) —
  treat that low confidence as a floor, not a downgrade: it stays
  needs-human until a human confirms which side of "mistyped password" vs.
  "credential stuffing that worked" it's on.
- A `log-secret-*` finding, or a real secret/token you spot **in the clear**
  reading the raw file directly (the engine already redacts evidence in the
  finding message — a raw-file sighting is its own incident, independent of
  any finding).
- A traversal/probe-path hit that **succeeded** (2xx) against a genuinely
  sensitive target (`/etc/passwd`, `.env`, cloud credentials, `.git/config`).
- Any of the above corroborated across **multiple log sources** for the same
  actor (e.g. the same IP in an access log and an auth-failure burst in an
  app log).

Adjudicate exactly like any other finding: `verify` → a `supported`/`partial`
verdict with an `exploitPath`, or leave it `needs-human` if you can't rule
either way. **Never** `dismiss` a high/critical finding you can't positively
refute.

## 6. Scope — what this pass does NOT do

- **Behavioral state is per-IP and bounded.** The aggregator tracks at most
  100,000 distinct IPs (first-seen; beyond the cap, an IP keeps its per-line
  signature/UA/secret findings but is not behaviorally aggregated —
  `LOGSTATS.json`'s `distinctIpsOverflowed` and a `truncation[]` entry say so
  when it happens). It also does not correlate ACROSS IPs (e.g. a botnet
  spreading a brute-force run across many low-volume sources each under
  threshold) — that's still a human correlation over `LOGSTATS.json` +
  `authFailures`.
- **No cross-file/cross-source correlation beyond shared IP state.** Findings
  from different log files in one run share the same bounded per-IP state (so
  a brute-force run split across an app log and an access log for the same IP
  is caught), but the engine doesn't reason about causality across sources —
  that narrative is still yours to write (§4).
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
