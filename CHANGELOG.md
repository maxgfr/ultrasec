# Changelog

All notable changes to this project are documented here, generated automatically from the [Conventional Commits](https://www.conventionalcommits.org/) by [semantic-release](https://github.com/semantic-release/semantic-release).

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
