# Detection, measured

Scores against **third-party labelled corpora** — not the fixtures in this repo.
`tests/fixtures/bench/` is a regression gate written by the same people who wrote the
rules, so a perfect score there proves the rules did not change, not that they are good.
These are the numbers that can be checked by someone who does not trust us.

Engine `1.42.0` · extraction tier `AST (tree-sitter)` · generated 2026-09-02

Detection follows the SATE convention: a case counts as detected when a finding **of its
CWE** has a path intersecting the case file.

**Read TPR as the headline and FPR with care.** ultrasec enumerates *candidates* for a human
to adjudicate: a sanitizer lowers a candidate's confidence and annotates it, it never
auto-dismisses. So every sanitized-but-reported case counts against FPR here even though
surfacing it is the intended behaviour — the `FP w/ sanitizer noted` column shows how many
of those the engine handed over *with the mitigating evidence already attached*. A tool that
auto-suppressed them would score better on this table and lose real bugs, which is the
trade this project has deliberately not made.

## OWASP Benchmark v1.2 (Java)

2740 cases · GPL-2.0 — fetched, never vendored · <https://github.com/OWASP-Benchmark/BenchmarkJava>

| CWE | TP | FN | FP | TN | TPR | FPR | FP w/ sanitizer noted | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-22 | 133 | 0 | 135 | 0 | 100.0% | 100.0% | 0/135 | 0.66 |
| CWE-327 | 130 | 0 | 116 | 0 | 100.0% | 100.0% | 0/116 | 0.69 |
| CWE-328 | 129 | 0 | 107 | 0 | 100.0% | 100.0% | 0/107 | 0.71 |
| CWE-330 | 218 | 0 | 173 | 102 | 100.0% |  62.9% | 0/173 | 0.72 |
| CWE-501 | 83 | 0 | 43 | 0 | 100.0% | 100.0% | 0/43 | 0.79 |
| CWE-614 | 36 | 0 | 31 | 0 | 100.0% | 100.0% | 0/31 | 0.70 |
| CWE-643 | 15 | 0 | 20 | 0 | 100.0% | 100.0% | 0/20 | 0.60 |
| CWE-78 | 126 | 0 | 125 | 0 | 100.0% | 100.0% | 0/125 | 0.67 |
| CWE-79 | 217 | 29 | 192 | 17 |  88.2% |  91.9% | 35/192 | 0.66 |
| CWE-89 | 272 | 0 | 232 | 0 | 100.0% | 100.0% | 53/232 | 0.70 |
| CWE-90 | 27 | 0 | 32 | 0 | 100.0% | 100.0% | 0/32 | 0.63 |

## Reading these honestly

- A corpus is not a codebase. Synthetic cases are small, single-file and unambiguous;
  they reward a pattern matcher and understate what cross-file analysis is for.
- A **0.00 Youden** row means the class was not enumerated at all on this stack — a
  coverage gap, and more useful to know than a good average.
- Every number here is the MECHANICAL half only: no scanners, no adjudication. The
  audit ultrasec actually produces has a human judging each candidate, which no
  benchmark of this shape can measure.
