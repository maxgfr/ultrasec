# Personal data — the mechanisms to hunt

A taint engine finds where untrusted data reaches a dangerous sink. It says
nothing about *whose* data flows where, how long it stays, or who else receives
it — and on an application built around personal data that is often the larger
half of the audit.

This file is a hunting guide for the `privacy` category, in the shape of the
other attack-class references: **mechanisms and the question that decides each
one**, not legal recitation. You are looking for a gap between what the code
does and what the system claims about the data it holds. Cite `[file:line]` like
any other finding; a privacy finding that can't point at code is an opinion.

> **Severity, calibrated.** Personal data reaching a party that was never meant
> to receive it is a real finding. A missing retention policy is a real finding.
> "This app processes personal data" is not — every app does. The bar is the
> same as everywhere else in this skill: name who is affected, by what
> mechanism, and what they lose.

---

## 1. Data crossing a processor boundary

The single highest-yield check. Personal data leaves the system every time it is
sent to something you don't run: an LLM API, an error tracker, an analytics
endpoint, a support tool, a log shipper.

**Find the egress points.** Every outbound HTTP client, SDK init, and telemetry
hook. Then, for each, read what is actually in the payload — not what the
variable is named.

```bash
rg -n "openai|anthropic|mistral|api\.openai|generativelanguage|bedrock" --type-add 'code:*.{ts,js,py,go,rb,java}' -tcode
rg -n "Sentry\.(init|setUser|captureException|captureMessage)|datadog|newrelic|bugsnag|posthog|mixpanel|segment"
rg -n "extra:\s*\{|setUser\(|setContext\(|setTag\(" -A3
```

Questions that decide it:

- Does the payload carry the user's own identifiers (email, name, id), or free
  text they wrote, or both?
- Which host does it actually reach? A base URL read from configuration means
  the destination is a deployment decision — say so, and name the configured
  production value rather than guessing.
- Is the recipient in the same jurisdiction and the same contractual perimeter
  as the rest of the system? For a public-sector or health application this is
  usually the finding, not a footnote.

**A worked shape.** An assistant sends the user's question to a third-party LLM.
The question is free text describing a real person's situation. The system's
answer to "is that ok?" is an anonymisation step — which brings us to §2.

## 2. A control that is narrower than its name

The most common privacy defect in practice: something called `anonymize`,
`redact`, `sanitize`, or `scrub` that removes far less than a reader assumes,
with the rest of the design leaning on it.

```bash
rg -n "def (anonymi|redact|scrub|pseudony)|function (anonymi|redact|scrub)" -A25
```

Read the implementation and enumerate what it actually covers. Then compare with
what the data really contains:

| Claimed | Frequently missing |
|---|---|
| named-entity removal (NER) | emails, phone numbers, postal addresses, dates of birth |
| "PII stripped" | national IDs, tax/social-security numbers, IBANs, licence plates |
| regex redaction | anything the model or the pattern doesn't recognise; the recall is never 100% |
| "anonymised" | in the GDPR sense, almost never — reversible ⇒ pseudonymised |

Two distinct findings live here, and they should be filed separately:

1. **The coverage gap** — the control misses category X, and X is present in the
   data. Show a concrete input that survives it.
2. **The load-bearing claim** — some *other* decision (a third-party transfer, a
   retention exemption) is justified by this control being an anonymisation when
   it is not.

## 3. Pseudonymisation that is trivially reversible

A hash of an identifier is not anonymous when the input space is small and the
salt is not secret.

```bash
rg -n "sha256|sha1|md5|createHash|hashlib" -B3 -A6
```

Decide it with three questions:

- **Is the salt secret?** A constant in the source, a public prefix, or no salt
  at all means anyone with the source and the database can rebuild the mapping.
- **Is the input space enumerable?** Corporate emails (`firstname.lastname@org`),
  sequential ids, phone numbers — all are dictionary-attackable in minutes.
- **How much is truncated?** Truncation reduces collision resistance but does not
  add secrecy; it never turns a reversible hash into an anonymous one.

If all three point the wrong way, the identifier is still personal data, and
anything the system does on the strength of "it's anonymised" is unsupported.

## 4. No retention, no erasure

Look for the absence of code rather than its presence — which is why a scanner
never finds this one.

```bash
rg -n "DELETE FROM|deleteMany|destroy\(|purge|retention|ttl|expire" 
rg -n "created_at|inserted_at" --glob '*migration*' --glob '*.sql'
```

- Is there **any** path that deletes a record once it is no longer needed — a
  cron, a TTL, a lifecycle rule, a manual endpoint?
- Can a person exercise access, rectification or erasure at all? If the only
  identifier stored is a hash (§3), the honest finding may be that erasure is
  *impossible by construction*, which is worse than merely missing.
- Do backups and the analytics warehouse inherit the same limit, or does the
  data outlive its deletion in a second store?

## 5. Data about people who never use the system

Free-text fields collect information about third parties: a support agent
describing a customer, a caseworker describing a claimant, a clinician
describing a patient. Those people cannot see a privacy notice, cannot consent,
and cannot exercise a right they don't know they have.

Ask: does any free-text field predictably contain third-party data? If yes, what
downstream flow (§1) does it feed, and what retention (§4) applies? This is
usually the structural finding on case-management, support and assistant-style
applications — and it is invisible to every scanner.

## 6. Personal data in logs and telemetry

Related to CWE-532 but broader: the payload need not be a credential to be a
problem.

```bash
rg -n "console\.log|print\(|logger\.(info|debug|warn|error)" -A2 | rg -i "user|email|body|payload|prompt|question|request"
rg -n "JSON\.stringify\((req|request|body|payload|user)"
```

- Does a debug log serialise a whole request or prompt?
- Do logs reach a different retention regime and a wider audience than the
  database they came from? They almost always do.
- Does an error path attach user content as diagnostic context (§1 covers where
  it then goes)?

## 7. Over-collection at the identity layer

Read the scopes and claims the application requests, then find where each is
used.

```bash
rg -n "scope[\"']?\s*[:=]|claims|authorization_params" -A3
```

A scope requested but never read is collected for nothing. Name the specific
unused ones — "requests too much" is not actionable.

---

## Reporting

File these as `category: "privacy"`, with the same discipline as any other
finding:

- **Cite the code.** The egress call, the anonymiser body, the hash, the missing
  deletion path (cite the migration or the model that has no lifecycle).
- **Name who is affected.** The user, or a third party who never used the system.
- **State the mechanism, not the regulation.** "The raw question is persisted and
  never deleted" is a finding; "violates Article 5(1)(e)" is a conclusion for
  the reader's DPO to draw. Mentioning the principle as context is fine; leading
  with it is not.
- **Separate a design decision from a defect.** "Production is configured to use
  a US-hosted model" is a decision with consequences — report it, but do not
  dress it as a vulnerability.

Related: [attack-classes.md](attack-classes.md) for the classes taint can't
reach · [severity-and-discipline.md](severity-and-discipline.md) for the
severity bar these findings must clear too.
