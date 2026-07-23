# Changelog

All notable changes to this project are documented here, generated automatically from the [Conventional Commits](https://www.conventionalcommits.org/) by [semantic-release](https://github.com/semantic-release/semantic-release).

# [1.12.0](https://github.com/maxgfr/ultrasec/compare/v1.11.0...v1.12.0) (2026-07-23)


### Bug Fixes

* **check:** stream-count lines so huge log files don't misreport as missing ([082a6ea](https://github.com/maxgfr/ultrasec/commit/082a6ea0dc6bccbb2042bf064f17053d4da90e99))
* **logs:** cap hygiene's embedded evidence line at 200 chars ([4169112](https://github.com/maxgfr/ultrasec/commit/4169112f6d547d1e006d09ec2df88948797f4df0))
* **logs:** match actuator/<endpoint> probe paths, not just bare /actuator/ ([6e1379b](https://github.com/maxgfr/ultrasec/commit/6e1379bbf68623c8bfd526d887eea937b8ac8e52))
* **logs:** redact query-string secrets before counting into stats.topPaths ([21b4be8](https://github.com/maxgfr/ultrasec/commit/21b4be88387946fccacac1b10957a24e239fe967))
* **logs:** reject unknown --format values instead of silently degrading ([6d26cd4](https://github.com/maxgfr/ultrasec/commit/6d26cd40c9b64b0b420b9e8db45c96d489b03238))
* **logs:** replace scan-only truncation advice with logs-appropriate wording ([52dcfde](https://github.com/maxgfr/ultrasec/commit/52dcfdec575e0c3c75c88a150ab319b19f590a04))
* **package-checker:** guard cache dir materialization to prevent scan crash ([4accf38](https://github.com/maxgfr/ultrasec/commit/4accf38d0b7fb317ded6b92b021e62031ac309d0))
* **package-checker:** skip the adapter on a repo-local data/*.purl feed ([7be31ca](https://github.com/maxgfr/ultrasec/commit/7be31cac0b809ded1bab47aefd7682eb2c6f48e0))
* **pm-audit:** guard Array.isArray for wrong-typed cves/via fields ([831412f](https://github.com/maxgfr/ultrasec/commit/831412fd9ebf1d95b5712ae7038b47ca07f48d15))
* **scan:** preserve the pre-adoption walk surface (byte cap, dossier dir) ([4d03162](https://github.com/maxgfr/ultrasec/commit/4d03162a6744597fc9df064f0a12dabf1106c7f3))
* **scan:** surface sbom field in --json output ([3e1f195](https://github.com/maxgfr/ultrasec/commit/3e1f195290622c9f6c28bdb02bb648289b43f715))
* **scan:** wire --max-candidates into the --log-hygiene pass ([cb656e8](https://github.com/maxgfr/ultrasec/commit/cb656e86a00fe6996890e7c01a5ecb7c39005b35))
* **tools:** address deferred review minors ([1543a19](https://github.com/maxgfr/ultrasec/commit/1543a199d4f92771a73eee0451be075be4cba37a))
* **tools:** exclude the run's out dir from syft's SBOM scan ([6ba02e6](https://github.com/maxgfr/ultrasec/commit/6ba02e60e4741d0359f2e88e6a3b934de3e42e60))
* **tools:** gate cargo-audit on Cargo.lock ([31ee57c](https://github.com/maxgfr/ultrasec/commit/31ee57cd207c4136d2ea9368070e2ac230f5b1da))
* **tools:** guard falsy entries in pip-audit and grype parse methods ([81848ff](https://github.com/maxgfr/ultrasec/commit/81848ff5de4770afcad5f546c55d882e4e8678d5))


### Features

* **docker:** bake grype/syft/pip-audit into the toolbox image ([3da671a](https://github.com/maxgfr/ultrasec/commit/3da671ae37c4db51dd82110c49f5dbb9bd597272))
* **logs:** add blue-team log-forensics command ([cb8a3f8](https://github.com/maxgfr/ultrasec/commit/cb8a3f823c9abfb5e9b7d2360549287f4791a2a9))
* **logs:** syslog/auth.log, behavioral aggregation, secret/PII leak findings ([8177321](https://github.com/maxgfr/ultrasec/commit/81773213dcbbd531d993dfd16cce232ef9f60a00))
* **sbom:** add syft SBOM producer + wire RunContext.sbom into scan ([9b8fe6f](https://github.com/maxgfr/ultrasec/commit/9b8fe6f9d0eaa379de86ba564239eca0b85ddba5))
* **scan:** add opt-in --log-hygiene static logging checks (CWE-117/CWE-532) ([a05cb7f](https://github.com/maxgfr/ultrasec/commit/a05cb7ff7292cb2664c67740e9e89a3d5095ab73))
* **tools:** add npm-audit/pnpm-audit/yarn-audit native adapters ([e95abb0](https://github.com/maxgfr/ultrasec/commit/e95abb0356e0d5134d8a8832d3a4358b2c6fa8cc))
* **tools:** add package-checker adapter for 12-ecosystem GHSA/OSV scanning ([765939a](https://github.com/maxgfr/ultrasec/commit/765939a8eb98b2e890789b5a13357540797dc6f1))
* **tools:** extend the runner contract for non-PATH adapters ([ea66a1d](https://github.com/maxgfr/ultrasec/commit/ea66a1da995acf054aaf1f3659d5880732e56e29))
* **tools:** wire grype and pip-audit adapters, drop osv-scalibr ([a9f642b](https://github.com/maxgfr/ultrasec/commit/a9f642bdff4fb2610044de6aa2e3df152b610295))

# [1.11.0](https://github.com/maxgfr/ultrasec/compare/v1.10.3...v1.11.0) (2026-07-23)


### Features

* **engine:** re-pin the codeindex engine at v2.11.0 ([80d12d8](https://github.com/maxgfr/ultrasec/commit/80d12d89d43b62542683b15530aefd21b23bd86f))

## [1.10.3](https://github.com/maxgfr/ultrasec/compare/v1.10.2...v1.10.3) (2026-07-22)


### Bug Fixes

* **resolve:** surface manifest files to the engine resolver ([7191b6b](https://github.com/maxgfr/ultrasec/commit/7191b6b011f60876afecadc25943d77e1007ba7b))

## [1.10.2](https://github.com/maxgfr/ultrasec/compare/v1.10.1...v1.10.2) (2026-07-10)


### Bug Fixes

* **check:** fail-closed on unknown/missing status in the semantic gate ([77e7c6b](https://github.com/maxgfr/ultrasec/commit/77e7c6b007e09b99e2c858fed5fae91029f82111))
* **git:** worktree-prefix the HEAD rev-expressions so subdir --repo git facts resolve ([d663b96](https://github.com/maxgfr/ultrasec/commit/d663b961a08d999ff59c5ce86a930f3838ceb59f))
* **graph:** honor --run so `graph <file|symbol> --run <run>` resolves from the run ([1b77a08](https://github.com/maxgfr/ultrasec/commit/1b77a088761b52ac7778ade3f5ca29d75a6d4756))

## [1.10.1](https://github.com/maxgfr/ultrasec/compare/v1.10.0...v1.10.1) (2026-07-09)


### Bug Fixes

* **orchestrate:** close the revalidate fold loop + fail-closed --apply parsing ([#5](https://github.com/maxgfr/ultrasec/issues/5)) ([e07b015](https://github.com/maxgfr/ultrasec/commit/e07b015ba7a3e3b526f6aa5b3a5bfa67e9d78a3d))

# [1.10.0](https://github.com/maxgfr/ultrasec/compare/v1.9.0...v1.10.0) (2026-07-09)


### Features

* **orchestrate:** emit multi-agent workflows + contracts + runbook per run ([#4](https://github.com/maxgfr/ultrasec/issues/4)) ([5a40628](https://github.com/maxgfr/ultrasec/commit/5a40628d602926bea2dcdcbb9a9d0bc96988af5f)), closes [hi#severity](https://github.com/hi/issues/severity)

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
