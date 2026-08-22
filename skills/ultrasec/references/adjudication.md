# Adjudication — deciding what's real

The engine hands you **candidates**, deliberately recall-oriented: it emits a flow whenever a
source and a sink connect across the graph, whether or not the flow is real. Turning that list
into a report is the whole job. This file is the method: the false-positive shapes you will
actually meet, how to refute each one, how to write the proof when it *is* real, and two worked
examples end to end.

Order of work per candidate: **restate the claim → read the packet → answer the four questions →
name the FP shape or write the exploit → record the verdict.** Never skip to the verdict.

## Step 0 — restate the claim before you analyse it

Half of false positives collapse the moment the claim is stated precisely, because most of them are
not wrong analyses — they are *vague* ones. Before opening a file, write the candidate back in your
own words:

- **Class** — what kind of bug is this claimed to be?
- **Trigger** — what does the attacker send, and to which entry point?
- **Impact** — what do they get that they did not already have?
- **Threat model** — who are they, and what do they already hold? (`CONTEXT.md`)
- **Preconditions** — what must be true of the caller, the config, the deployment?

If you cannot fill in the trigger, the candidate is not yet a claim and the honest verdict is
`unsupported`. If you cannot fill in the impact, check brocard 2 before going further: an exploit
that requires what it grants is not an exploit.

## Route: standard or deep

Not every candidate deserves the same spend. Decide once, at step 0.

| | Standard verification | Deep verification |
|---|---|---|
| **When** | one component, a known class, a direct flow | ambiguous claim, several components, concurrency, or logic with no written spec |
| **Work** | read the path, answer the four questions, verdict | reconstruct the invariant the code assumes, look for the caller that breaks it, consider interleavings, and have a second pass try to refute your own conclusion |
| **Escalate** | when the four questions do not settle it | — |

Treating every candidate as deep exhausts the budget before the interesting ones; treating every
candidate as standard is how a race condition gets marked `unsupported`.

## The four questions

`dossier <id>` prints them at the bottom of every packet. They are not a formality — each has a
failure mode that produces a different verdict.

| # | Question | If the answer is no |
|---|---|---|
| 1 | Is the SOURCE genuinely attacker-controlled? | `refuted` — see FP-1, FP-2 |
| 2 | Does the tainted value reach the sink through **every** hop, unchanged? | `refuted` — see FP-5, FP-6, FP-7 |
| 3 | Is there a sanitizer / validator / authz guard on the path? | if it fully covers the flow, `refuted` — FP-3, FP-4 |
| 4 | Is the SINK exploitable **with the value that arrives**? | `unsupported` (or `partial` if it's exploitable only under conditions you can't confirm) |

A "yes" to all four obliges you to write the `exploitPath`. If you can't write it, you haven't
answered question 4 — go back, don't downgrade.

## The false-positive taxonomy

Twelve shapes cover almost every spurious candidate. Name the shape in your verdict `note` —
it makes the report reviewable and it is what `triage` (`noise|keep`) is actually deciding.

**FP-1 · The source isn't untrusted.** `process.env` and `process.argv` are catalogued sources
because they *often* are — but an env var read at boot from an operator-controlled deployment,
or an argv value in a developer script, is not attacker input. Ask *who can set this in
production*. → Refute by naming the setter and showing no request path reaches it.

**FP-2 · The source is attacker-*visible* but not attacker-*controlled*.** A request header the
framework normalizes (a parsed `Host` validated against an allow-list), an id the router coerces
to an integer before the handler sees it. → Refute by citing the coercion/validation `[file:line]`.

**FP-3 · A sanitizer on the path already covers it.** The catalog lowers confidence when it sees
one but never auto-dismisses, because a sanitizer can be present and *not apply*. Confirm three
things before refuting: it runs on **this** path (not a sibling branch), it neutralizes for
**this** sink's context, and nothing after it re-introduces the value.
When the sanitizer is a WRAPPER around a library, none of those three can be answered from the
repository — see *Question 3 sometimes lives in `node_modules`* below.
*Sanitizers that look sufficient and aren't:* `basename()` doesn't stop an absolute path or a
Windows drive-relative one; `parseInt`/`Number` are decisive only if the **coerced** value is
what reaches the sink (re-stringifying the original is common); `DOMPurify` with
`ALLOW_UNKNOWN_PROTOCOLS` or on a non-HTML context; `yaml.safe_load` is safe but
`yaml.load(x, Loader=yaml.Loader)` is not; `escapeshellarg` behaves differently on Windows;
HTML escaping does nothing inside a `<script>` block, an attribute without quotes, or a `href`.

**FP-4 · The framework already escapes it.** Jinja2/Twig/ERB autoescape, React text nodes, Go's
`html/template` (but **not** `text/template`), a JSON response with a non-HTML content type. →
Refute by citing the template engine's configuration, not by assuming the default.

**FP-5 · The sink isn't a sink here.** `exec` of a constant; `db.query` on a literal;
`readFile` on a path built entirely from internal constants. The callee name matched; the call
doesn't do the dangerous thing.

**FP-6 · The tainted value isn't the argument.** The most common shape on short paths: the sink
sits one line after the source, and the graph links them, but the value actually passed is the
**return of another call**. `res.send(readDoc(doc))` sends file contents, not `doc`. Before you
refute, check the second-order question — can the attacker control the *returned* value through
their input? If yes it's a real finding with a different story; if no, refute.

**FP-7 · Same-name, different symbol.** The graph resolves by name; two modules exporting
`get`/`query`/`run` can produce a hop that doesn't exist at runtime. → Refute by showing the
import in the calling file resolves elsewhere.

**FP-8 · The path is unreachable.** Dead code, a route never registered, a branch behind a flag
that is off in production, an unexported function with no caller. → Refute by citing the
registration site (or its absence). Careful: "unreachable" claimed from the graph alone is weak —
the graph is a summary and misses framework dispatch.

**FP-9 · Not in the shipped artifact.** Tests, fixtures, `examples/`, build scripts, gitignored
scratch trees. Real for a developer machine, not for the deployed service. → Refute *and* say
which artifact you scoped to; re-scan with `--gitignore` or `--exclude` if it's noise at scale.

**FP-10 · The ORM parameterizes despite the concatenation.** A query builder that looks like
string-building but binds. Inverse trap: an ORM does **not** bind identifiers — table/column
names, `ORDER BY`, `LIMIT`, and `IN (…)` list construction are never parameterizable, so
"we use an ORM" is not a refutation for those.

**FP-11 · Defense-in-depth, not a vulnerability.** The attack is already prevented by a layer
you found. That is a `hardeningNotes` entry, not a finding, and it gets no severity
(see [severity-and-discipline.md](severity-and-discipline.md)).

**FP-12 · Duplicate of a finding you already have.** Same root cause, same fix, different line.
Fold it — the correlator does this for tool findings; for AI discoveries, an `investigate --apply`
at an existing finding's location folds into its `sources` automatically.

> **The refutation bar is asymmetric on purpose.** For low/medium/info, a well-argued FP shape
> is enough. For **high/critical**, only an explicit, cited refutation dismisses — the apply
> policy sends everything else to `needs-human` (`unsupported` on high/critical, and `partial`
> at **any** severity). Not being able to prove it is not the same as disproving it.

## Writing the proof (`exploitPath`)

`exploitPath` is required on every `supported` verdict. It is what turns a claim into a report
someone can act on, and writing it is how you discover you were wrong.

A complete one carries: **the trigger** (method, path, headers, body — literal, not described),
**the precondition** (unauthenticated? which role? what state?), **what comes back** (the
observable that proves it), and **the impact in one clause**.

```
POST /api/reports  ·  unauthenticated  ·  body: {"name":"x; sleep 5 #"}
→ response takes 5s (baseline 40ms), proving shell execution as the app user
```

Discipline that keeps a PoC safe and credible:

- **Prove, don't damage.** `sleep(5)` timing over `DROP TABLE`; `SELECT 1` or a boolean
  differential over dumping a table; an internal 127.0.0.1 fetch over the cloud metadata
  endpoint; a `<b>` tag over a cookie-stealer. The point is to demonstrate control, not to use it.
- **Blind/OOB when there is no reflection.** Time-based for SQLi and command injection,
  response-size or status differentials for enumeration, a DNS/HTTP callback for SSRF where the
  response never returns. State which one you used.
- **Reason-only is allowed, and must be labelled.** If you can't run the target, say
  "not executed — reasoned from `[file:line]`" in the `note`. An unexecuted PoC built on an
  assumption about a parser or runtime is the most convincing kind of false positive; cite the
  spec or the code, don't assert behaviour.
- **The exploit is the regression test.** Hand the same payload to
  [implement-playbook.md](implement-playbook.md) — a fix verified by a test that doesn't use the
  real payload isn't verified.

## Triage: `noise` vs `keep`

`triage` is a glance, not a read: one line per candidate, no code. Spend it on the shapes you can
recognize without opening a file.

- **`noise`** — the citation is in a test/fixture/vendored/generated path (FP-9); the class is
  structurally impossible for the stack (a `buffer` candidate in pure TypeScript); a
  logging-hygiene finding on a call you can see is a literal string. Only bites on
  low/medium/info — a `noise` on high/critical is **ignored by design** and goes to full verify.
- **`keep`** — everything else, and always when the title names a class the app's trust model
  makes serious. Cheap to keep; expensive to lose a real bug.

If deciding needs the code, it isn't triage — leave it `keep` and adjudicate properly.

## Rationalizations that end an audit early

Each of these is a thought that feels like a conclusion and is actually a shortcut. Catching one
means stopping and doing the step it replaced.

| Thought | Why it's wrong | Do instead |
|---|---|---|
| "This pattern is dangerous, so it's a bug" | The pattern is the hypothesis, not the finding | Trace the flow end to end |
| "The same code was vulnerable in that other repo" | Each context has its own callers and guards | Adjudicate this one on its own evidence |
| "It's obviously critical, no need to be rigorous" | Severity raises the cost of being wrong, not the licence to skip | Apply the same four questions, then try to refute yourself |
| "The scanner rated it high" | A tool's severity is a prior with no knowledge of your app | Brocard 7 — judge the code |
| "I can't find the caller, so it's unreachable" | Dynamic dispatch, DI and framework routing are invisible to the graph | `unsupported`, not `refuted` (brocard 3) |
| "There's a validator on the line, so it's fine" | A validator that checks the wrong property protects nothing | Read what it actually rejects |
| "It's behind auth, so it's low" | An authenticated user is an attacker in most threat models | Brocard 2 — check what the precondition really costs |
| "Too many candidates to read them all" | The count is a budgeting problem, not an evidence problem | `triage`, `--min-severity`, and the **Reachability evidence** block in each dossier (scope tier · def-use · does anything tainted reach the assigned value) — then read what's left. `--strict-scope` is the blunt version: it discards the whole `file` tier rather than letting you judge it. |

## Question 3 sometimes lives in `node_modules`

A house sanitizer is a wrapper, and the wrapper is not where the bug is. `xssWrapper` around
`xss@1.0.15`, `sanitizeHtml` with a custom `transformTags`, a `DOMPurify` call with hooks — the
repo's own code is a config object, and whether that config holds is decided inside the library.

The audit that produced this section found two bypasses of one such wrapper, and **neither could be
seen from the repository**. Both were in the options: an `onTagAttr` hook returning a value, which
short-circuits the library's own `safeAttrValue` and with it every URL-scheme check; and an
`onIgnoreTag` hook re-emitting the raw tag with its attributes intact. You confirm that by opening
`node_modules/xss/lib/parser.js` and reading what the hook's return value does — nothing else
proves it, and nothing else refutes it either.

Since the default prune, that tree is not in the scan. So when question 3 turns on a wrapper you
did not write, go and get it:

```bash
ultrasec scan --repo . --out .ultrasec --include-vendored --scope node_modules/xss --sinks
# and to just READ it, which is usually what you want:
#   rg -n 'onTagAttr|safeAttrValue' node_modules/xss/lib/
```

Scoped, on purpose. `--include-vendored` across a whole repository is how an audit ends up with 561
findings from a tree nobody maintains — that is exactly why the prune exists. Pointed at the one
package a verdict depends on, it is the difference between "a sanitizer is present" and a verdict
you can defend.

Three shapes worth the trip: a hook or callback whose RETURN VALUE the library acts on; an
allow-list you extended (`allowedTags`, `ALLOWED_ATTR`) where the addition re-opens a class; and a
version whose behaviour you are asserting from memory. If you cannot read the library, the honest
verdict is `needs-human` with the question written down — not `refuted` because a sanitizer was on
the line.

## After the batch: look for chains

Findings are adjudicated one at a time; attackers do not use them one at a time. Once a batch is
done, re-read the `unsupported` and low-severity pile together and ask what **composes**:

- an information leak that supplies the id another finding needs;
- an open redirect plus a token in a URL;
- a path traversal limited to reads, next to a config file the app re-loads;
- a rate-limit gap that turns a 1-in-10⁴ race into a reliable one.

A chain is reported as **one finding** at the severity of the outcome, citing every link. This is
where the genuinely critical results usually come from — no single link looked like much.

## Worked example 1 — a confirmed 3-file SQLi

Run against `tests/fixtures/vuln-chain` (`scan --tools none` → 8 candidates). Candidate
`7e51071c4783`, HIGH, CWE-89, path `src/routes.js:12 → src/routes.js:13 → src/service.js:6 →
src/db.js:7`. `dossier 7e51071c` (ids accept a unique prefix) prints the real code at each hop:

```
### 1. [SOURCE] src/routes.js:12   _untrusted input (http): req.query_
>>   12 |   const id = req.query.id;

### 2. [HOP] src/routes.js:13      _calls lookupUser()_
>>   13 |   const row = lookupUser(id);

### 3. [HOP] src/service.js:6 — in lookupUser()   _calls runQuery()_
      5 |   const sql = "SELECT * FROM users WHERE id = " + id;
>>    6 |   return runQuery(sql);

### 4. [SINK] src/db.js:7 — in runQuery()   _sql sink: query()_
>>    7 |   return conn.query(sql);
```

Answering the four questions against that code:

1. **Source** — `req.query.id` on a route registered at `routes.js:11` with no auth middleware.
   Attacker-controlled by any unauthenticated client. ✅
2. **Propagation** — `id` is passed positionally at :13, concatenated verbatim at `service.js:5`,
   and the resulting string is the sole argument at `db.js:7`. Nothing reassigns or re-parses it. ✅
3. **Guard** — none on the path. Not FP-10: `conn.query(sql)` receives one pre-built string, with
   no parameter array (contrast `sqlite.query("… = ?", [id])` in the `vuln-express` fixture,
   which is why that sibling is correctly never emitted). ✅
4. **Sink** — a raw MySQL statement in a numeric context, unquoted, so no quote-escape is even
   needed. ✅

```json
{ "id": "7e51071c4783", "verdict": "supported",
  "note": "req.query.id concatenated at service.js:5, reaches conn.query() unparameterized; no guard on any hop.",
  "exploitPath": "GET /user?id=1%20OR%201=1 · unauthenticated → returns every row of `users`, proving the value is parsed as SQL, not data" }
```

`verify --apply` → `confirmed`. Then `revalidate` asks whether it still exists at HEAD.

## Worked example 2 — a refuted candidate

Same run, candidate `8104ef108b3e`, HIGH, CWE-94, path `scratch/leftover.js:3 →
scratch/leftover.js:4`:

```
3 | const arg = process.argv[2];
4 | eval(arg);
```

Structurally this is real: a CLI source reaches `eval` in one hop, unguarded. Question 1 is where
it dies. `scratch/` is listed in the repo's `.gitignore`; the file ships in no artifact and is
reachable only by someone who already has shell on the box — at which point `eval` is not the
weakest link. That is **FP-9**, and it is also FP-1 (an argv value in developer debris is not
attacker input).

```json
{ "id": "8104ef108b3e", "verdict": "refuted",
  "note": "FP-9: scratch/ is gitignored developer debris, in no shipped artifact; the only 'attacker' who can pass argv here already has shell. Re-scan with --gitignore to drop the whole tree." }
```

Two things this example teaches beyond the verdict: **scope is part of the claim** — say which
artifact you audited — and a repeating FP-9 is a *scan* problem, not a verdict problem. Fix it
with `--gitignore`/`--exclude` so the next pass never spends attention on it.

## Worked example 3 — the shape that needs a second look

The same run emits three MEDIUM reflected-XSS candidates, e.g. `409b0c792964`,
`src/routes.js:25 → src/routes.js:26`:

```
25 |   const doc = req.query.doc;
26 |   res.send(readDoc(doc));
```

The BFS saw a tainted value on :25 and an XSS sink on :26 and linked them. But the argument to
`res.send` is `readDoc(doc)` — the **file contents**, not `doc`. That is **FP-6**, and the lazy
move is to refute and move on.

Don't. Ask the second-order question: the attacker chooses *which file* is read (`files.js:5`
concatenates into `"docs/" + doc` with no confinement — the very traversal candidate
`558bbf00b3b0` reports). So they can point it at any readable file and have its bytes returned
with `res.send`'s default `text/html`. The XSS claim as stated is wrong; the **information
disclosure is worse than the XSS**, and it belongs to the traversal finding.

```json
{ "id": "409b0c792964", "verdict": "unsupported",
  "note": "FP-6: res.send receives readDoc(doc), not doc — the query param is not reflected. The attacker-controlled *content* comes from the unconfined read at files.js:5; impact is carried by finding 558bbf00b3b0, not duplicated here." }
```

This is the pattern to internalize: **an FP shape tells you the stated claim is wrong, not that
there is nothing there.** Follow the value one more step before you close it.

---

Related: [severity-and-discipline.md](severity-and-discipline.md) (how to rate what survives) ·
[schemas.md](schemas.md) (the exact verdict JSON) ·
[citation-format.md](citation-format.md) (the grounding contract) ·
[attack-classes.md](attack-classes.md) (what to look for that the engine can't enumerate).
