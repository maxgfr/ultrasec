# Changelog

All notable changes to this project are documented here, generated automatically from the [Conventional Commits](https://www.conventionalcommits.org/) by [semantic-release](https://github.com/semantic-release/semantic-release).

# [1.9.0](https://github.com/maxgfr/ultrasec/compare/v1.8.0...v1.9.0) (2026-07-08)


### Bug Fixes

* **check:** accept line 0 as a file-scoped citation; keep rejecting out-of-range and negative lines ([7dbfb34](https://github.com/maxgfr/ultrasec/commit/7dbfb34c8ec0ba78be3471d5ce155c676a11ed33))
* **correlate:** merge dep advisories per package across installed versions, recording per-version locations ([7b80c9a](https://github.com/maxgfr/ultrasec/commit/7b80c9ac9ca61c225f5d7f8033cd8733195a5f7d))
* **scan:** correlate taint, orphan-sink and tool findings in one pass so co-located same-CWE findings dedupe ([9ae63d8](https://github.com/maxgfr/ultrasec/commit/9ae63d8d2385474755b5afc27151e4532a1d7e0b))


### Features

* **catalog:** receiver-gated SSRF member-call sinks (axios.get, requests.get, session.post, …) ([4caeba1](https://github.com/maxgfr/ultrasec/commit/4caeba15b95ce5fc55a166a9f60b29e5ac819fe3))
* **clean:** preserve report deliverables by default; add --all for full removal ([8c837b2](https://github.com/maxgfr/ultrasec/commit/8c837b2ba96c485d0b2951e8a0b1194b7bfa6bf3))
* **scan:** persist and render per-tool run status (ran/empty/skipped/failed) ([64c8128](https://github.com/maxgfr/ultrasec/commit/64c812864f25c37663f8056e84b900e45a9b0665))

# [1.8.0](https://github.com/maxgfr/ultrasec/compare/v1.7.1...v1.8.0) (2026-07-04)


### Features

* **report:** merge REPORT and FULL tiers into one complete report ([5b9be23](https://github.com/maxgfr/ultrasec/commit/5b9be23f6f3d965757d0a80f90dfd233d570aaa7))

## [1.7.1](https://github.com/maxgfr/ultrasec/compare/v1.7.0...v1.7.1) (2026-06-28)


### Bug Fixes

* **skill:** package under skills/ultrasec/ so `skills add` bundles the engine ([cbea3dd](https://github.com/maxgfr/ultrasec/commit/cbea3dde416072723f20c034db14846af65532bd))

# [1.7.0](https://github.com/maxgfr/ultrasec/compare/v1.6.1...v1.7.0) (2026-06-25)


### Features

* **skill,narrative:** add hunting heuristics, severity discipline, and positive-patterns + hardening-notes report sections ([c86da82](https://github.com/maxgfr/ultrasec/commit/c86da82c79f0f262edea605ffbcdf21249243934))

## [1.6.1](https://github.com/maxgfr/ultrasec/compare/v1.6.0...v1.6.1) (2026-06-18)


### Bug Fixes

* **graph:** escape NUL separators in keyOf so sources stay text-only ([9c7e3a9](https://github.com/maxgfr/ultrasec/commit/9c7e3a9c4434377e7d9b7b0abd3b8f4e31f9534c))
* **parser,correlate:** honor short flags, stop boolean-flag token theft, gate taint corroboration by CWE ([ef0f368](https://github.com/maxgfr/ultrasec/commit/ef0f3689ec0ffea1f608aa3f1642cf4d8d4a34aa))

# [1.6.0](https://github.com/maxgfr/ultrasec/compare/v1.5.0...v1.6.0) (2026-06-18)


### Features

* **context:** project-context primer injected into dossier + verify worklist ([0a73c75](https://github.com/maxgfr/ultrasec/commit/0a73c757fe043590798a6f21e536bb3fef8091b8))
* **deepsec:** correlate onto taint paths + ingest priorAnalysis as a signal ([3cd2fa2](https://github.com/maxgfr/ultrasec/commit/3cd2fa2147fe80d93d8ad8d93b29995bfa70ced2))
* **implement:** remediation-PRD draft stage fed to the to-prd skill ([1db1dab](https://github.com/maxgfr/ultrasec/commit/1db1dab4569a743c0c6412bae5c6d783a33ea934))
* **investigate:** agentic-discovery stage ingesting grounded ultrasec-ai findings ([cd06a17](https://github.com/maxgfr/ultrasec/commit/cd06a17fbb5cd4e9597559fa766993249657f133))
* **narrative:** AI-authored report sections via `render --narrative` ([7351017](https://github.com/maxgfr/ultrasec/commit/7351017cfbc77619df5eea3a771d9e1a2cba034f))
* **revalidate:** git-history false-positive cut (deepsec-style revalidate pass) ([5717564](https://github.com/maxgfr/ultrasec/commit/57175644718dc707e49ff6603b5aa1820ecc8d42))
* **run:** opt-in powered mode driving an external agent CLI over the worklists ([6c077f8](https://github.com/maxgfr/ultrasec/commit/6c077f8a6d8376194d426e7b7d6b6b3f380b7df6))
* **stage:** shared emit→apply harness; refactor verify onto it (byte-identical) ([32cbaf5](https://github.com/maxgfr/ultrasec/commit/32cbaf562c317928ec0617f888d796ce0a863c79))
* **triage:** cheap code-free quick-dismiss fast-lane over open candidates ([ef38871](https://github.com/maxgfr/ultrasec/commit/ef3887102c0dabc160c630a95ecf77aadeee10ad))

# [1.5.0](https://github.com/maxgfr/ultrasec/compare/v1.4.0...v1.5.0) (2026-06-18)


### Features

* **import:** ingest deepsec exports as a correlated, grounded source ([451a0c6](https://github.com/maxgfr/ultrasec/commit/451a0c69f42d363a58833a1678094c540573a8d2))
* **scan:** orphan-sink recall (--sinks) and git-blame provenance (--blame) ([8f4d0f2](https://github.com/maxgfr/ultrasec/commit/8f4d0f22837b9b341841da374938677933c1e3b7))

# [1.4.0](https://github.com/maxgfr/ultrasec/compare/v1.3.0...v1.4.0) (2026-06-18)


### Bug Fixes

* harden against the prototype-key bug class + gitignore/symlink/merge correctness ([8a9834d](https://github.com/maxgfr/ultrasec/commit/8a9834d1888ba47b69ed620e6dc3a809fcd7a5db)), closes [hi#severity](https://github.com/hi/issues/severity)
* prototype-key crash in graph merge / taint reads ([2265085](https://github.com/maxgfr/ultrasec/commit/22650859faff365e3cab10d1f6b30125ef8ca36f))
* round-2 audit — symlink under-scan, gitignore fidelity, truncation clear ([ebc18b4](https://github.com/maxgfr/ultrasec/commit/ebc18b425fcda89d3b3e85a98cd4210953c1e2a6)), closes [#literal](https://github.com/maxgfr/ultrasec/issues/literal)
* round-3 audit — make globToRe total (no crash) + drop unsafe artifact name-filter ([8c873d0](https://github.com/maxgfr/ultrasec/commit/8c873d08b35a8c5ae8ac7515488a5f5c9fb6034f))


### Features

* scale to large repos — attack-surface map, scoped/incremental scans, O(edges) taint ([a6d6c4b](https://github.com/maxgfr/ultrasec/commit/a6d6c4bd154d8a3c4ede96db093cb53849d01707))

# [1.3.0](https://github.com/maxgfr/ultrasec/compare/v1.2.0...v1.3.0) (2026-06-17)


### Features

* cross-tool correlation, EPSS/KEV/CVSS risk scoring, SARIF + 5 new scanners ([6163626](https://github.com/maxgfr/ultrasec/commit/6163626ba2617dd134d11a7e4ae94d0e8bbb384f))

# [1.2.0](https://github.com/maxgfr/ultrasec/compare/v1.1.1...v1.2.0) (2026-06-16)


### Features

* `clean` command — tidy up everything ultrasec creates, from the script ([79abbb9](https://github.com/maxgfr/ultrasec/commit/79abbb9a549c1be891da5be263074261da7753ac))

## [1.1.1](https://github.com/maxgfr/ultrasec/compare/v1.1.0...v1.1.1) (2026-06-16)


### Bug Fixes

* normalize all tool finding paths to repo-relative (native + docker) ([7cc65a1](https://github.com/maxgfr/ultrasec/commit/7cc65a169808d58928dffd1cbb0649ebcd196aaa))

# [1.1.0](https://github.com/maxgfr/ultrasec/compare/v1.0.0...v1.1.0) (2026-06-16)


### Features

* Docker tool orchestration + skill install docs + real-repo validation ([c6a8824](https://github.com/maxgfr/ultrasec/commit/c6a8824d8e6df8f6d0a75a8408527bb3b060e25a))

# 1.0.0 (2026-06-16)


### Bug Fixes

* address 11 issues from the adversarial self-review ([ac101d6](https://github.com/maxgfr/ultrasec/commit/ac101d6787a70a646cc23384c9dc95fe8594df02))


### Features

* cross-file link-graph engine (~15 languages) ([0e0a191](https://github.com/maxgfr/ultrasec/commit/0e0a191d15065e9eeacf799b33cac715d8b41a42))
* orchestrate external scanners (Trivy, OpenGrep, gitleaks, osv, cargo-audit, govulncheck) ([5531842](https://github.com/maxgfr/ultrasec/commit/55318427fe184b2c4899310c289a91f75610523f))
* SKILL.md + references (the agent skill) ([dbba613](https://github.com/maxgfr/ultrasec/commit/dbba613cf65d1e50cc50c8b56e19476046df09bd))
* taint catalog + cross-file source→sink candidate engine ([0dfe5d8](https://github.com/maxgfr/ultrasec/commit/0dfe5d856b613d86e715a55203a6998148b86fe7))
* verify gate + grounding check + tiered report/HTML render ([fb328e7](https://github.com/maxgfr/ultrasec/commit/fb328e73d6aa74ef08fc4107df4c4554929107d5))
