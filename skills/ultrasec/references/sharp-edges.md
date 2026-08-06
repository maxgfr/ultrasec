# Sharp edges — when the API invites the mistake

Every other lens in this skill asks *is this code vulnerable?*. This one asks a different question,
and it is the right one whenever the repo ships a library, an SDK, a framework or a public API:

> **Does this design make the insecure use easier than the secure one?**

The governing principle: **secure usage should be the path of least resistance.** A component with
no vulnerability of its own, that reliably produces vulnerabilities in everything built on it, is
the higher-impact finding — it scales, and each downstream victim looks like their own bug.

Use it when the audit target is consumed by other code. Skip it for a leaf application.
`investigate --lens sharp-edges` sets the frame; the classes below are the checklist.

## The six categories

### 1. Algorithm or mode chosen by the caller

Offering a choice invites the wrong one. The canonical case is JWT: because the token declares its
own `alg`, an attacker sets `"alg": "none"`, or flips RSA to HMAC and signs with the public key.
The library was not vulnerable — it did what it was asked.

*Look for:* an algorithm/mode/curve parameter with no allow-list, a cipher argument accepting a
string, a `verify()` that reads the algorithm from the data it is verifying.

### 2. Dangerous defaults, and the ambiguous zero

A setting whose default is the insecure value, or whose zero has two plausible meanings.
`lifetime=0`: never expires, or already expired? Whichever the implementer chose, half the callers
assume the other.

*Look for:* `verify: false`, `strict: false`, `insecure_skip_verify`, TLS verification off by
default, and any numeric option where 0 or `-1` means "unlimited" without saying so at the call
site.

### 3. Primitive types instead of semantic ones

When a nonce, a key and a salt are all `[]byte` / `bytes` / `Buffer`, the compiler cannot stop you
swapping them, and eventually somebody does.

*Look for:* cryptographic material passed as raw bytes or strings; ids, tokens and secrets all
typed `string`; argument lists of three or more same-typed parameters.

### 4. Configuration cliffs

One setting, silently wrong, and the whole control is gone. A YAML typo that no schema rejects; an
environment variable that overrides a hardened default without a warning; a policy file that fails
**open** when it cannot be parsed.

*Look for:* config loaded without validation, unknown keys ignored, and the error path on a
malformed policy — if it logs and continues, that is the finding.

### 5. Silent failures

Verification that "succeeds" on malformed input. A missing key that returns a falsy value the
caller compares loosely. An exception swallowed by a helper that then returns a default.

*Look for:* a `verify`/`validate`/`check` that returns a value rather than throwing, and every
caller that ignores it; `except: pass`; `catch {}`; a signature check whose failure branch is
indistinguishable from its success branch.

### 6. Stringly-typed security

Permissions as `"read,write"`, roles as free text, scopes concatenated then split. Every one of
those is an injection point and a typo away from privilege.

*Look for:* comparisons against string literals for authorization, `includes()`/`in` on a
comma-joined permission string, and role names built by concatenation.

## The three adversaries

Model all of them; only the first is malicious.

1. **The attacker** — actively looks for the mode you left switchable.
2. **The copy-paster** — takes the first snippet from your README or from Stack Overflow. If that
   snippet is insecure, so is every downstream deployment.
3. **The confused developer** — reads the documentation, misreads one word, holds the API the wrong
   way round. If two reasonable readings exist, the design is the defect.

## Rating one

Severity here measures **how easy the mistake is**, not how exploitable one instance is:

| | |
|---|---|
| **Critical** | the obvious, documented usage is insecure |
| **High** | a plausible misconfiguration silently removes the control |
| **Medium** | an unusual but reachable configuration does |
| **Low** | it takes deliberate misuse |

## Arguments that do not hold

- *"It's documented."* Documentation does not undo a dangerous default. Compare brocard 5 in
  [dismissal-brocards.md](dismissal-brocards.md): documented behaviour excuses the *implementation*,
  not the *design* — and a footnote has never stopped a copy-paster.
- *"Advanced users need the flexibility."* Then gate it behind a name that says so
  (`dangerouslyAllowUnverified`) and make the safe path the default.
- *"Changing it would break compatibility."* A real cost, and an argument about the fix, not the
  finding. Report it, note the constraint, let the maintainer decide.
