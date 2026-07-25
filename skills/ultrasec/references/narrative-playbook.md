# Narrative playbook (writing the report)

`render` alone produces a correct, cited, tiered report that reads like a list. `NARRATIVE.json`
is what makes it a report someone acts on: what it means, what to fix, what's already good, and
what isn't a finding at all.

```
ultrasec narrative --run .ultrasec          # → NARRATIVE.todo.json + NARRATIVE.md
# author <run>/NARRATIVE.json
ultrasec render --run .ultrasec --narrative NARRATIVE.json
```

Emit-only: nothing here changes a finding's status, severity, or the set of findings. Full field
shape and a filled example are in [schemas.md](schemas.md).

## What each section is for

**`executiveSummary`** — three to five sentences for someone who will not read the findings.
State the shape of the risk, not the count. *"Two confirmed injection flaws in a public API, both
exploitable unauthenticated; both come from the same helper that string-builds queries and
commands."* Avoid the count-as-headline ("23 findings") — it rewards padding and tells the reader
nothing about exposure. Say what an attacker gets, and say what would have to be true for this to
be worse than stated.

**`positivePatterns`** — what the codebase does well, honestly. This is not politeness: it
calibrates trust in the findings you *did* report, and it stops a team reading a short report as
a shallow one. "Every write path outside these two goes through the parameterizing builder" tells
a reader the two are anomalies, not the tip of an iceberg.

**`remediations`** — one per confirmed finding: `{id, fix, patch?, owner?}`. The `fix` is a
sentence a developer can act on without re-reading the finding. `patch` is a diff sketch when the
change is small and unambiguous.

> **Check every remediation against its CWE before you submit.** The grounding gate verifies the
> id is confirmed; it does **not** verify the fix matches the vulnerability. A command-injection
> fix pasted onto an XSS finding passes every check and ships. Per-class fix patterns are in
> [implement-playbook.md](implement-playbook.md).

**`attackChains`** — where the report earns its keep. Findings that are individually rated
MEDIUM can compose into a CRITICAL path: information disclosure reveals an id, an IDOR fetches
it, a missing rate limit brute-forces the id space. Name the chain, list the `findingIds` in
order, and describe the path. Don't inflate the individual severities to make the point — that's
what this section is for.

**`rootCauses`** — group findings by the mistake that produced them, not by CWE. Three SQLi
findings in one helper are one root cause and one fix; three in three unrelated files are a
process problem worth naming as such. `implement` uses these groups to structure the remediation
plan, and without a narrative it derives them mechanically by `(category, cwe)` — which is
usually less useful than what you'd write.

**`hardeningNotes`** — defense-in-depth suggestions that are explicitly **not** findings: no
severity, excluded from the counts, never inflated into the findings table. This section is what
lets you stay disciplined about the exploitability bar in
[severity-and-discipline.md](severity-and-discipline.md) without discarding real advice. If you
catch yourself arguing that something is "technically a LOW", it belongs here.

## What gets checked, and what doesn't

Sections that cite finding ids — `remediations`, `attackChains`, `rootCauses` — are
grounding-checked and **dropped** if an id is unknown or not `confirmed`. A dropped section is
silent in the output, so if a remediation you wrote isn't in the report, check the id's status
first.

The advisory prose — `executiveSummary`, `positivePatterns`, `hardeningNotes` — cites no ids and
is kept as written. It is also clearly labelled **AI-authored** in the rendered report, alongside
the deterministic sections. Don't erase that distinction by mixing verified claims into it: if a
sentence needs to be trusted, it should cite a finding.

## Writing the report itself

- **Impact without hyperbole.** "Returns every row of `users` to an unauthenticated client" beats
  "catastrophic data breach". The concrete claim is checkable and therefore more persuasive.
- **No "potentially".** If the word is load-bearing, the finding isn't finished — go back to the
  code or leave it `needs-human`.
- **Say what you didn't cover.** Which scopes, which classes, whether the run hit a truncation
  cap, whether external scanners were skipped, and whether `manifest.extraction.ast` was `false`
  (a regex-tier run is a materially thinner audit). A report that doesn't state its coverage
  reads as complete.
- **Recommend the next pass.** One pass reads only the paths you dug into. Name the classes and
  regions this one under-covered so a `--merge` re-run has a target.
- **An honest "no exploitable vulnerabilities found" is a valid result** — after you have pushed
  hard enough to believe it.

## Then hand it to remediation

`implement --run <run>` folds the just-authored narrative into `IMPLEMENT.md` — fix stories
grounded in their `[file:line]`, grouped by your root causes, with your suggested fixes and
patches carried through. See [implement-playbook.md](implement-playbook.md).
