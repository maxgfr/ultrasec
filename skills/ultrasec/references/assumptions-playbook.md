# The assumption map — what the code trusts that nothing enforces

Most stages ask *is this candidate real?*. This one runs before there are candidates, and asks a
different question of every unit of code:

> **What does this function guarantee, and what does it depend on without checking?**

The second list is the output. A function that trusts its caller to have verified ownership,
called by a caller that trusts the function to verify it, is a vulnerability present in **neither
function's code**. There is no dangerous call to match, no tainted value to trace, and nothing
wrong on any single screen — which is precisely why taint enumeration cannot reach it and why
reading file by file keeps missing it.

```bash
ultrasec assumptions --run <dir>                        # units, ordered by untrusted-input load
ultrasec assumptions --apply ASSUMPTIONS.json --run <dir>
```

Run it after `context` and before `investigate`. Its leads land in the next `investigate` emit.

## What to record per unit

```json
{ "at": "src/orders.js:42",
  "guarantees": [
    { "claim": "returns only orders whose tenantId matches the session", "file": "src/orders.js", "line": 47 }
  ],
  "assumptions": [
    { "claim": "the caller has already checked the user owns :orderId", "enforcedAt": "nothing-found" },
    { "claim": "`id` is a positive integer", "enforcedAt": "src/routes.js:31" }
  ],
  "calls": [
    { "callee": "db.findOrder", "expectedBehavior": "no implicit tenant scoping — the filter must be passed" }
  ],
  "openQuestions": ["is `req.session.tenantId` set for API-token requests, or only for cookie sessions?"] }
```

Four rules make this stage worth its cost:

1. **A guarantee needs the line that establishes it.** If you cannot cite one, it is not a
   guarantee — it is an assumption, and it belongs in the other list. This single reclassification
   is where most of the leads come from.
2. **`nothing-found` is a result, not a gap in your notes.** Write it when you looked and there is
   no enforcement. Leaving the field vague is how the finding gets lost.
3. **No severity, no verdict, no finding.** Understanding first. Forcing a rating out of an
   observation this early is how an uncomfortable one gets talked away — and an unenforced
   assumption is not a vulnerability, it is where to look for one.
4. **List open questions; never guess them.** A guessed answer here propagates silently into every
   later stage as though it were established.

## Reading order

Follow the calls, not the file listing. For each unit: what must be true on entry, what is true on
return, and what it hands to the things it calls. Trace the paths that fail, not only the ones that
succeed — the interesting assumption is usually the one that holds on the happy path and is never
re-checked on the retry, the cache hit, or the batch endpoint.

## What the leads become

`--apply` writes two things:

- **`ASSUMPTIONS.md`** — the map, unenforced assumptions first.
- **`ASSUMPTIONS.leads.json`** — picked up by the next `investigate` emit and printed under the
  region it belongs to, so the hunt starts from named gaps instead of a blank prompt.

A lead is a question carried into the hunt. It becomes a finding only when `investigate` produces a
grounded `Discovery` and `verify` confirms it — the same bar as everything else. Filing "this is
unverified" as a vulnerability is exactly the padding
[severity-and-discipline.md](severity-and-discipline.md) exists to prevent.

## Where this pays

| shape | what the map surfaces |
|---|---|
| Broken access control | the helper that filters by id but not by tenant, and every caller that assumes it does both |
| IDOR | the function that takes an id it never checks the requester may see |
| Business logic | the invariant one path maintains and another silently skips |
| Race / TOCTOU | the value checked once and assumed stable across an await |
| Trust boundaries | an internal-only helper reached from a public route |

Every one of these is an **absence**. The engine enumerates presences; this is how you enumerate
the absences.
