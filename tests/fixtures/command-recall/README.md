# Fixture for issue #10 (defect 2)

One file per real-world process-execution shape, one per language. Splitting the
single `languages: ["*"]` command rule into gated per-language ones is exactly the
kind of change that quietly loses a language, so every file here must still
produce a CRITICAL CWE-78 finding.
