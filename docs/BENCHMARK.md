# Detection, measured

Scores against **third-party labelled corpora** — not the fixtures in this repo.
`tests/fixtures/bench/` is a regression gate written by the same people who wrote the
rules, so a perfect score there proves the rules did not change, not that they are good.
These are the numbers that can be checked by someone who does not trust us.

Engine `1.21.0` · extraction tier `AST (tree-sitter)` · generated 2026-08-06

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
| CWE-22 | 118 | 15 | 102 | 33 |  88.7% |  75.6% | 0/102 | 0.67 |
| CWE-327 | 101 | 29 | 99 | 17 |  77.7% |  85.3% | 0/99 | 0.61 |
| CWE-328 | 98 | 31 | 86 | 21 |  76.0% |  80.4% | 0/86 | 0.63 |
| CWE-330 | 177 | 41 | 142 | 133 |  81.2% |  51.6% | 0/142 | 0.66 |
| CWE-501 | 72 | 11 | 33 | 10 |  86.7% |  76.7% | 0/33 | 0.77 |
| CWE-614 | 36 | 0 | 31 | 0 | 100.0% | 100.0% | 0/31 | 0.70 |
| CWE-643 | 7 | 8 | 7 | 13 |  46.7% |  35.0% | 0/7 | 0.48 |
| CWE-78 | 115 | 11 | 89 | 36 |  91.3% |  71.2% | 0/89 | 0.70 |
| CWE-79 | 195 | 51 | 135 | 74 |  79.3% |  64.6% | 2/135 | 0.68 |
| CWE-89 | 183 | 89 | 129 | 103 |  67.3% |  55.6% | 0/129 | 0.63 |
| CWE-90 | 11 | 16 | 11 | 21 |  40.7% |  34.4% | 0/11 | 0.45 |

## Reading these honestly

- A corpus is not a codebase. Synthetic cases are small, single-file and unambiguous;
  they reward a pattern matcher and understate what cross-file analysis is for.
- A **0.00 Youden** row means the class was not enumerated at all on this stack — a
  coverage gap, and more useful to know than a good average.
- Every number here is the MECHANICAL half only: no scanners, no adjudication. The
  audit ultrasec actually produces has a human judging each candidate, which no
  benchmark of this shape can measure.
