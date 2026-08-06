# The grounds for a dismissal

`Only dismiss what you can positively refute` is the right rule and, on its own, an unfalsifiable
one: it never says what a refutation may consist of. So in practice a tired adjudicator writes
"looks like a false positive", the finding disappears, and nobody can tell afterwards whether that
was analysis or fatigue.

A **brocard** is a named, falsifiable ground. Each one below is a test a reviewer can disagree
with — which is the entire point. A dismissal that names a brocard is auditable; a dismissal that
names none is an abandonment wearing a verdict's clothes.

> Adapted from William Woodruff's *Brocards for vulnerability triage*.

Set it in the verdict row:

```json
{ "id": "a1b2c3", "verdict": "refuted", "brocard": "outside-usage",
  "note": "buildReport() is only called from scripts/nightly.mjs, which runs under cron with a constant argument; no route reaches it." }
```

`check --semantic` lists every high/critical dismissal that names no ground. It **reports**, it does
not fail — a gate that failed here would just teach adjudicators to pick a ground to get green, and
the rule above it (never auto-dismiss what you merely cannot confirm) already carries the weight.

---

## 1. `no-threat-model` — no vulnerability without a threat model

The claim must complete: **an attacker with [X] can [Y] to obtain [Z]**. If any of the three is
missing, there is no finding yet — there is a pattern.

*Use when* the candidate names a dangerous call but no attacker who reaches it.
*Do not use* merely because the threat model is unwritten. Reconstruct it from `CONTEXT.md` first;
"I did not think about who the attacker is" is not the same as "there is no attacker".

## 2. `exploit-from-the-heavens` — no exploit from the heavens

If the capability the attack **requires** already equals or exceeds what it **grants**, the
vulnerability is redundant. Command injection reachable only by someone who can already run
commands is not a privilege boundary being crossed.

*Use when* the precondition is admin, root, local shell, or write access to the source.
*Do not use* when the precondition is merely *authenticated*. A logged-in user is an attacker in
almost every threat model, and most real breaches start from one.

## 3. `outside-usage` — no vulnerability outside of usage

Behaviour that is theoretically possible but unreachable in any real deployment. The vulnerable
path exists; nothing calls it, or nothing calls it with attacker-controlled data.

*Use when* you have traced the callers and can name what does reach the code.
*Do not use* for "I could not find a caller". Absence of a call edge in the graph is a limit of the
graph — dynamic dispatch, reflection, framework routing and DI containers are all invisible to it.
Not finding the path is `unsupported`, not `refuted`.

## 4. `standard-behavior` — no vulnerability from standard behavior

The behaviour is the specification working as written. The defect, if any, is in the standard.

*Use when* you can cite the clause.
*Do not use* when the implementation voluntarily promised something stricter and fails to hold it —
that broken promise is the finding.

## 5. `documented-behavior` — no vulnerability from documented behavior

The behaviour is documented, security implications included, at the boundary where a caller would
look. Downstream misuse is then a downstream defect.

*Use when* the documentation actually states the security consequence, not just the mechanics.
*Do not use* to excuse a dangerous default. "Documented" and "safe by default" are different claims,
and a footnote does not make an insecure default secure — see
[sharp-edges.md](sharp-edges.md), which treats exactly that as its own class of finding.

## 6. `cure-worse-than-disease` — no cure worse than the disease

Remediation would cause more harm than the issue does: a breaking change across a large dependency
graph, a rewrite of a critical path, an availability risk out of proportion to a low-impact bug.

*Use when* you have named the fix and its blast radius.
*Do not use* to dismiss the **finding**. This brocard argues about the *remediation*, so the honest
outcome is usually a confirmed finding with a documented risk acceptance — not a dismissal. Reach
for it only when the issue is genuinely marginal.

## 7. `report-not-dispositive` — the report is neither necessary nor sufficient

A CVE id, a scanner's severity, a bug-bounty submission: none of them prove a vulnerability exists,
and their absence proves nothing either. Judge the technical merits.

*Use when* the only evidence is provenance or a score.
*Do not use* to wave away a scanner hit you have not read. This brocard licenses you to look past
the metadata, not past the code.

---

## The two failure modes this list exists to prevent

**Dismissing by vibe.** Every ground above is checkable by someone else. If you cannot state which
one applies, you have not refuted the finding — you have stopped working on it, and the correct
verdict is `unsupported` (which leaves a high/critical at `needs-human`, exactly where it belongs).

**Treating the list as a menu.** Brocards are a vocabulary for refutations you already have, not a
set of exits to be searched for. If you find yourself trying each in turn to see which might stick,
that is the signal the finding is real and you are looking for permission to drop it.
