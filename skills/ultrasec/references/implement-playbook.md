# Implement playbook (remediation planning → `to-prd`)

Once an audit has confirmed and reported its findings, the last mile is **driving the
fix**. `implement` turns the audited dossier into a **remediation-PRD draft**
(`IMPLEMENT.md`): every confirmed finding becomes a fix work item grounded in its
`[file:line]` with an acceptance-criteria scaffold, needs-human findings become
investigation items, and they're grouped by root cause. You feed that draft to the
local **`to-prd`** skill to author the actual PRD, or hand it to an implementer/AI.

`implement` mirrors `narrative`: it is **emit-only**, has **no `--apply`**, and it
**never changes a finding's status/severity/set** and persists nothing to the dossier.
The engine emits a grounded worklist; the `to-prd` skill (or an agent) does the authoring.

## 1. Emit the remediation worklist

```
ultrasec implement --run .ultrasec
```

Writes:
- `IMPLEMENT.md` — the remediation-PRD draft (Problem statement, Solution grouped by
  root cause, User stories / work items, Investigation items, Out of scope).
- `IMPLEMENT.todo.json` — the structured worklist: `fixes[]`, `investigations[]`,
  `rootCauses[]`, and the `dismissed` count.

**Only `confirmed` findings become fix items**; `needs-human` become investigation
items; `open`/`dismissed` are excluded (dismissed is counted for "Out of scope"). Run
`verify --apply` first so the dossier actually has confirmed findings to plan around.

## 2. Fold in the narrative (recommended)

If you authored a `NARRATIVE.json` (see
[the narrative step](../SKILL.md)), `implement` folds its grounded **suggested
fixes / patches / owners** and **root-cause groups** into the draft automatically when
`<run>/NARRATIVE.json` exists — or point at one explicitly:

```
ultrasec implement --run .ultrasec --narrative NARRATIVE.json
```

The narrative is run through the **same confirmed-only grounding gate** (`mergeNarrative`)
that `render` uses, so a fix citing an unknown or non-confirmed id is dropped. Without a
narrative, fix items are left as stubs and root causes are **derived deterministically**
by `(category, cwe)` over the confirmed findings.

## 3. Author the PRD with `to-prd` (or hand off)

`IMPLEMENT.md`'s headings deliberately match the `to-prd` template. Feed it to the skill:

```
/to-prd        # then point it at <run>/IMPLEMENT.md
```

The `to-prd` skill owns publishing/config — ultrasec never calls a tracker (its keyless,
network-free core is untouched). Alternatively, hand `IMPLEMENT.md` straight to an
implementer or coding agent: every work item already carries its grounded `[file:line]`
and an acceptance-criteria scaffold (the cited line is no longer exploitable + a
regression test reproduces-then-passes).

## 4. Fix patterns per class

The draft carries *your* suggested fix from `NARRATIVE.json`, or a stub. These are the patterns
worth reaching for, and — more useful — the ways each is commonly got wrong.

| class | the fix | the trap |
|---|---|---|
| **SQLi (CWE-89)** | bind every value: `?`/`$1`/`:name` placeholders | **identifiers can't be bound.** Table/column names, `ORDER BY`, `LIMIT`, and `IN (…)` list-building need an allow-list of literals, not a parameter |
| **Command injection (CWE-78)** | argv array — `execFile`/`spawn` without a shell, `subprocess.run([...], shell=False)` | an argv array stops *shell* metacharacters, not **argument injection (CWE-77)**: `--upload-pack=`, `-o ProxyCommand=`, `--output=`. Add a `--` terminator and validate the value |
| **Path traversal (CWE-22)** | resolve, then confine: `realpath`/`filepath.EvalSymlinks`, then assert the result is inside the base dir | `path.join`/`filepath.Join` *clean* but do not *confine*. `basename` alone misses absolute and drive-relative paths. Check after resolution, not before — symlinks |
| **Zip-slip** | reject entry names that escape after resolution; cap entry count and total size | validating the archive name instead of each **entry** name |
| **SSRF (CWE-918)** | resolve the host to an IP, validate the **IP** against an allow-list, then connect to that IP; disable redirects or re-validate each hop | validating the URL string, then letting the client re-resolve (DNS rebinding) or follow a 302 |
| **XSS (CWE-79)** | contextual output encoding at the sink, by the template engine | one escaper for all contexts. HTML-escaping does nothing inside `<script>`, an unquoted attribute, or a `href` (where `javascript:` is the payload). Sanitize on **output**, not on input |
| **Deserialization (CWE-502)** | a data-only format — `JSON.parse`, `yaml.safe_load` — plus a schema | allow-listing classes in an unsafe deserializer; the gadget surface is the whole classpath |
| **SSTI (CWE-1336)** | never build a template from user input; pass it as a *variable* to a fixed template | escaping the input instead of moving it out of the template source |
| **Prototype pollution (CWE-1321)** | reject `__proto__`/`constructor`/`prototype` keys, or use `Map`/`Object.create(null)` | a shallow guard on a deep merge |
| **Weak crypto (CWE-327/338)** | bcrypt/scrypt/argon2 for passwords; `crypto.randomBytes`/`secrets`/`SecureRandom` for tokens; AEAD with a unique IV | replacing MD5 with SHA-256 for password hashing — still far too fast |
| **Timing leak** | `timingSafeEqual`/`compare_digest`/`MessageDigest.isEqual` | early-return comparison written by hand |
| **IDOR / missing authz** | enforce ownership **in the query** (`WHERE owner_id = ?`) as well as post-load | fixing the one route you found; check every path to the same state change, including bulk and export |
| **Mass assignment (CWE-915)** | an explicit allow-list of settable fields | a deny-list, which the next migration silently defeats |

**Fix the root cause once.** If three findings share a helper, the work item is the helper — that
is what the `rootCauses` grouping is for. Three unrelated instances of the same class is a
different signal: it's a process gap, and it belongs in the narrative.

## 5. Execute the fixes

Each confirmed finding's acceptance criteria are the definition of done:

1. The cited `[file:line]` is no longer exploitable for that finding.
2. A regression test reproduces the issue before the fix and passes after it — **using the
   finding's own `exploitPath` payload.** A test written from the finding's *title* passes
   against a fix that only blocks the obvious shape; the recorded payload is what proved the bug,
   so it is what must stop working.

Investigation items (needs-human) must be resolved first — confirm whether each is
exploitable, then route it to a fix or dismiss it.

Sequence by exploitability, not by severity label: anything unauthenticated and remotely
reachable is a hotfix; everything behind auth can be scheduled. A finding with no available fix
(an unpatched dependency) gets compensating controls and an explicit owner, not an impossible
ticket.

## In `run` / powered mode

`implement` is the **final stage** of `run` (after `narrative`), so it folds the
just-authored narrative. In the keyless default, `run` emits `IMPLEMENT.md` +
`IMPLEMENT.todo.json` with **zero external calls**. In `--powered` mode the agent reads
the draft and authors a complete remediation PRD as a **local file** (`REMEDIATION_PRD.md`)
— no tracker publish, keeping powered runs free of outward-facing side effects. See
[powered-mode.md](powered-mode.md).
