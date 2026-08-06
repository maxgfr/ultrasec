# Threat modelling — deciding what to look for before you look

`context` establishes what the app is. This decides what you will *hunt*, and it is the difference
between an audit and a checklist walk. Without it every finding is rated in the abstract and the
hunt goes wherever the tooling happens to point.

Write the result into `CONTEXT.md`; `assumptions` and `investigate` both read it.

## STRIDE, per trust boundary

A trust boundary is anywhere data crosses from one level of trust to another: browser → server,
service → service, tenant → shared store, CI → production. For each one, decide which of the six
you actually care about and which you have accepted. Naming what you *accepted* matters as much as
naming what you fear — it stops the audit re-litigating it, and it makes the acceptance visible if
it was wrong.

| | threat | the control that answers it | what a finding looks like |
|---|---|---|---|
| **S** | Spoofing | authentication | a token accepted without verifying its signature or audience |
| **T** | Tampering | integrity | an id or price the client sends and the server trusts |
| **R** | Repudiation | audit logging | a privileged action with no attributable record |
| **I** | Information disclosure | confidentiality | an object returned without checking the requester may see it |
| **D** | Denial of service | availability | an unbounded query, an unbounded regex, an unbounded upload |
| **E** | Elevation of privilege | authorization | a role field the user can set; an admin route guarded only by the UI |

The last row is the highest-yield class in almost every audit, and the one no taint walk reaches.
It is also where `assumptions` pays: elevation bugs are usually an absent check, not a present one.

## LINDDUN, for personal data

Security asks *can an attacker get in*. Privacy asks a different question — *what happens to the
data when everything works as designed*. Run this pass over any repo that touches personal data;
it finds things STRIDE structurally cannot.

| | threat | the question |
|---|---|---|
| **L** | Linking | can two records be joined to build a profile nobody consented to? |
| **I** | Identifying | does "anonymised" survive contact with a join against something public? |
| **N** | Non-repudiation | is someone provably tied to an action they were entitled to deny? |
| **D** | Detecting | does the mere existence of a record leak something (a password-reset oracle)? |
| **D** | Data disclosure | where does it go — a processor, a log, an analytics beacon? |
| **U** | Unawareness | is it collected for a purpose the user was never told about? |
| **N** | Non-compliance | is there a retention period, and does anything enforce it? |

Mechanism-level method: [privacy-and-data-protection.md](privacy-and-data-protection.md).

## Business logic — the class with no payload

A logic flaw has no dangerous call and no tainted value. It has a **rule the code was supposed to
enforce and does not**, so the only way to find one is to know the rule. That is why this belongs
in the threat model rather than in the scan.

Recurring shapes:

| shape | what to try |
|---|---|
| Workflow skipping | call step 3's endpoint without doing 1 and 2 |
| Price / quantity tampering | negative quantity, fractional cents, a price field the client sends |
| Coupon / discount stacking | apply twice, apply concurrently, apply after the total is computed |
| Race on a balance or a quota | two requests in flight against one check-then-act |
| Replay | re-send a signed request; re-use a one-time token after success |
| State not re-checked | cancel an order after shipping; edit a submission after review |
| Quota bypass | a batch endpoint that counts one request but performs a hundred |

Report one as a **violated rule**, not as a payload:

| rule | expected | actual |
|---|---|---|
| A coupon applies once per order | second `POST /coupon` rejected | second call stacks; 200 with the discount applied twice |

That table *is* the finding. Severity comes from the business impact, not from a CWE — which is
why the calibration in [severity-and-discipline.md](severity-and-discipline.md) matters more here
than anywhere else.

## Rating what you find: likelihood × impact

For the classes with no CVSS vector, the OWASP Risk Rating factors keep two auditors within a
band of each other:

**Likelihood** — skill required · motive · opportunity (access needed) · population size ·
ease of discovery · ease of exploit · awareness (is it public?) · intrusion detection (would you
notice?).

**Impact, technical** — loss of confidentiality · integrity · availability · accountability.
**Impact, business** — financial damage · reputation · non-compliance · privacy violation.

The business row is the one that is usually skipped and usually decides. "An attacker reads any
user's invoice" is a medium technical finding and a regulatory event; rate it as the latter, and
say which factor drove the rating so a reader can disagree with the reasoning rather than the
number.
