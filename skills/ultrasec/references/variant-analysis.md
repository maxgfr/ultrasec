# Variant analysis — the other instances

Every stage before this one asks *is this candidate real?*. This one asks the question that
actually closes an audit: **where else does the same root cause appear?**

One bad habit produces many instances — a helper everyone calls without the guard, a validator
applied on three routes out of five, a pattern copy-pasted between two services by the same person
in the same week. Confirming one and stopping leaves the rest in production. They are also the
cheapest bugs in the whole audit to find, because you already know exactly what you are looking for.

```bash
ultrasec variants --run <dir>                     # one seed per CONFIRMED finding
ultrasec variants --apply VARIANTS.json --run <dir>
```

Seeds are **confirmed findings only**. Hunting variants of a candidate you have not proved
multiplies a guess; hunting variants of a proved bug multiplies knowledge.

## The five steps

### 1. State the root cause — the *why*, not the *what*

> ✗ "SQL injection in `getUser`"
> ✓ "every helper in `db/` builds its statement by concatenation, because the wrapper added in
> 2023 never accepted parameters — so the guard is per-caller and most callers forgot"

The *what* generalizes to nothing. The *why* tells you which axes to search: other callers of that
wrapper, other wrappers written from the same template, other places the same author solved the
same problem.

### 2. Build an exact match first, and check it hits the known instance

Write a pattern that matches **only** the bug you already confirmed, and run it.

**A pattern that returns zero results means you have misunderstood the bug.** Everything
downstream is then invalid — you would be generalizing from a shape that does not exist. This step
costs thirty seconds and is the only thing standing between a careful hunt and a confident one.

### 3. Generalize one dimension at a time

Abstract a single element, run, read **every** result, decide. Then the next.

Common axes:

| axis | the question |
|---|---|
| same sink callee | who else calls this dangerous helper? |
| same caller | what else does this caller do without the guard? |
| same interface | which sibling implementation was not fixed? |
| same file / module | copy-paste and parallel business logic |
| same critical type | what else touches this state object without the invariant? |
| type edge cases | null, empty, negative, boundary — the paths tests never take |

Abstracting two elements at once makes the new noise unattributable: you cannot tell which
relaxation produced it, so you cannot undo the wrong one.

### 4. Stop when over half the matches are false

That is the signal the pattern has left the family. Back up one step and keep that.

### 5. Record the patterns that failed

A hunt that reports only its successes is indistinguishable from a hunt that stopped early. The
failed patterns are the evidence the space was actually walked — keep them in `patterns[]` with
what each returned.

## Neighbours are places to look, not findings

`variants` pre-lists the mechanical neighbours it can already see (same sink callee, same file,
same CWE). These are **starting points**. Proximity is not a finding, and a neighbour still has to
survive the same adjudication as anything else: variants fold in as `Discovery[]` through the same
citation gate as `investigate`, so a variant citing a line that does not resolve is rejected exactly
like any other invented location.

## The output is a rule, not just a list

Write `regressionRule` while the bug is still in front of you — a Semgrep rule that catches the
whole family:

```yaml
- id: db-helper-unparameterized
  mode: taint
  pattern-sources:
    - pattern: req.$ANY
  pattern-sinks:
    - pattern: $CONN.query("..." + $X)
  pattern-sanitizers:
    - pattern: $CONN.query($SQL, $PARAMS)
  message: SQL built by concatenation — pass parameters instead.
  languages: [javascript, typescript]
  severity: ERROR
  metadata: { cwe: "CWE-89", owasp: "A03:2021" }
```

`--apply` collects these into `<run>/ultrasec-variants.yaml`. This is where an audit stops being a
document: a finding is fixed once, a rule keeps it fixed. The project gets the guard along with the
bug, and the next person to reintroduce the pattern is told by CI rather than by the next audit.

## Failure modes

1. **Searching only the module the bug was in.** Root causes travel with people and templates, not
   with directories.
2. **A pattern so tight it only matches the original.** That is step 2's job, not the hunt's.
3. **Hunting the vulnerability class instead of the root cause.** "find more SQLi" is a different,
   much worse search than "find the other callers of this wrapper".
4. **Testing only the success path.** Null, empty and boundary inputs are where the sibling
   instances usually differ from the seed.
5. **Reporting neighbours as findings.** They are candidates; adjudicate them.
