# Changelog

All notable changes to this project are documented here, generated automatically from the [Conventional Commits](https://www.conventionalcommits.org/) by [semantic-release](https://github.com/semantic-release/semantic-release).

## [1.60.1](https://github.com/maxgfr/ultrasec/compare/v1.60.0...v1.60.1) (2026-10-08)


### Bug Fixes

* **catalog:** stop filing state setters and modal open() as sinks ([1cf1987](https://github.com/maxgfr/ultrasec/commit/1cf1987d1247a13bf293280128b3ffc4ea4397b6))
* **correlate:** fold semgrep's mutable-action-tag into agentic-CI vector J ([788e624](https://github.com/maxgfr/ultrasec/commit/788e6248be87e7abf3e4d20071c913230f673408))
* **dossier:** compact CONTEXT.md in --brief packets ([5879515](https://github.com/maxgfr/ultrasec/commit/58795156b84363b9f285ff7b31ea5d4931a5a361))
* **map:** keep the test harness counted but out of the ranking ([465e4b5](https://github.com/maxgfr/ultrasec/commit/465e4b57514d6e4043ff29575f838b0b41474645))
* **tools:** report osv-scanner with no package sources as skipped ([998efcb](https://github.com/maxgfr/ultrasec/commit/998efcbad7eaf27b7e8d56fc66f5350309556370))

# [1.60.0](https://github.com/maxgfr/ultrasec/compare/v1.59.0...v1.60.0) (2026-10-08)


### Features

* **deps:** re-pin package-checker at v1.11.74 ([37d4940](https://github.com/maxgfr/ultrasec/commit/37d49407eb98bc87e7621e1138590381fb77a08d))

# [1.59.0](https://github.com/maxgfr/ultrasec/compare/v1.58.0...v1.59.0) (2026-10-07)


### Bug Fixes

* **resolve:** keep the scan when the engine cannot index a file type ([eda80de](https://github.com/maxgfr/ultrasec/commit/eda80de0b312a688c4690789800abe5900f93067))


### Features

* **catalog:** label framework idioms with a version range and put them in the matrix ([a4bec98](https://github.com/maxgfr/ultrasec/commit/a4bec987cfab78730a99dd0f6c30a201d31875f1))
* **classes:** hunt whole columns — packless, unknown and out-of-range frameworks ([5ab7cf8](https://github.com/maxgfr/ultrasec/commit/5ab7cf8ac94d3fd59f38ac6ad1a13b25ef988908))
* **classes:** port the framework postures from webconfig onto classes and packs ([daf8547](https://github.com/maxgfr/ultrasec/commit/daf854739c7823d7476c9defe347e0a0258664fd))
* **deps:** re-pin package-checker at v1.11.72 ([1d9feed](https://github.com/maxgfr/ultrasec/commit/1d9feedf0a9f7f292e6a5e282b88b2c7b6a6a498))
* **frameworks:** one stack table for the context brief and the matrix ([36d04e3](https://github.com/maxgfr/ultrasec/commit/36d04e37a168eeef60d160bebb655e8d63cd1675))
* **guards:** auth and throttle markers supplied by the detected packs ([1d1843f](https://github.com/maxgfr/ultrasec/commit/1d1843fc1739c53635926b600ca32e5edbb5df6b))

# [1.58.0](https://github.com/maxgfr/ultrasec/compare/v1.57.0...v1.58.0) (2026-10-07)


### Bug Fixes

* **classes:** match a credential env var whose whole name is the suffix ([62f5f22](https://github.com/maxgfr/ultrasec/commit/62f5f22fb3d190903c1f11c84c8c43ab1422bd58))
* **frameworks:** version `spring` as Spring Boot only ([7751693](https://github.com/maxgfr/ultrasec/commit/7751693e298c5a9895a7bea92adb6af662fc210c))


### Features

* **classes:** idiom packs for Node, Python, Java, Go, Ruby and PHP frameworks ([28930c9](https://github.com/maxgfr/ultrasec/commit/28930c9876e1ca2f44d49de40b6d62af3d14c758))
* **coverage:** weakness-class × framework matrix with testedWith degradation ([010e4b6](https://github.com/maxgfr/ultrasec/commit/010e4b6c88360b30cb8cbee477873d462c64d53a))
* **frameworks:** detect web frameworks and their versions per package ([f9a9211](https://github.com/maxgfr/ultrasec/commit/f9a9211a014564d09a3ebf1ae02f02a691b34047))
* **investigate:** hunt uncovered class × framework cells, collect pack suggestions ([3efd737](https://github.com/maxgfr/ultrasec/commit/3efd737704ec67a3cb0dfecfef805cf5b9209ef5))

# [1.57.0](https://github.com/maxgfr/ultrasec/compare/v1.56.0...v1.57.0) (2026-10-07)


### Bug Fixes

* **catalog:** tRPC procedures and Drizzle sql templates are not SQL sinks ([b941d9a](https://github.com/maxgfr/ultrasec/commit/b941d9ad05ddaed3725a5bddfb3a793f9f18d7fd))
* **check:** a "with no `X`" clause after a generic subject is not a claim ([35d98fc](https://github.com/maxgfr/ultrasec/commit/35d98fcf15764cc05315a5b4b6d665dfa273ab5c))
* **guards:** a logout route is not an authentication endpoint ([8f6862f](https://github.com/maxgfr/ultrasec/commit/8f6862f86d941a03dc55f1a25e60c81b4017c79c))
* **guards:** skip test files and fold wrapped handlers into their route ([4025bec](https://github.com/maxgfr/ultrasec/commit/4025bec5ae9a359de21ac13e2895e6865f12bf9e))
* **paths:** add --min-severity and say what an exact --severity hides ([f89a48a](https://github.com/maxgfr/ultrasec/commit/f89a48abcb2adeaa1fb54dd97f53122ef9fdade5))
* **store:** collapse duplicate finding ids instead of refusing the run ([516c7db](https://github.com/maxgfr/ultrasec/commit/516c7dbc96e349cd33a07577a6abcfed00db6032))
* **tools:** include the package in dependency finding ids ([702721d](https://github.com/maxgfr/ultrasec/commit/702721dc0801fb4cfb19e80c78358c824d606b07))
* **tools:** name the lockfile-installed version on package-checker manifest hits ([77a6ef9](https://github.com/maxgfr/ultrasec/commit/77a6ef9384c1f71ad491e756bb62400bf5e42abe))
* **tools:** scan a snapshot of tracked files with gitleaks, history on request ([156cba5](https://github.com/maxgfr/ultrasec/commit/156cba50869ded886fafb1553052069f20dc9dd9))
* **webconfig:** a cookie flag bound to an expression is set, not missing ([b2fdf0d](https://github.com/maxgfr/ultrasec/commit/b2fdf0d35a290e4409fc3efc30e3ca904ffc1973))


### Features

* **actions:** flag pull_request jobs that hand secrets to the PR's code ([851d1d4](https://github.com/maxgfr/ultrasec/commit/851d1d494675fb157626de5987c3083e9d141982))
* **authtokens:** flag timing-unsafe secret checks and leftover session chunks ([c88fff0](https://github.com/maxgfr/ultrasec/commit/c88fff01d33ff2eb886fbd7e964924f18a7cdfae))
* **cloud:** flag admin-UI ingresses, public compose ports and .env in images ([34550e6](https://github.com/maxgfr/ultrasec/commit/34550e6fc007fcf6fa070ec50ce7bfe025208065))
* **webconfig:** add CSV formula, env coercion, XFF, export and header shapes ([b3ddeba](https://github.com/maxgfr/ultrasec/commit/b3ddeba2d9d2bd0a4b8ac95158c17d393d5c3edc))

# [1.56.0](https://github.com/maxgfr/ultrasec/compare/v1.55.1...v1.56.0) (2026-10-06)


### Features

* **deps:** re-pin package-checker at v1.11.70 ([457e46f](https://github.com/maxgfr/ultrasec/commit/457e46f85f2b629f52e9c9fd82b55741264f8fa9))

## [1.55.1](https://github.com/maxgfr/ultrasec/compare/v1.55.0...v1.55.1) (2026-10-05)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([fd8698f](https://github.com/maxgfr/ultrasec/commit/fd8698f134d7539afe7f5f835c1453f58269aad4))

# [1.55.0](https://github.com/maxgfr/ultrasec/compare/v1.54.0...v1.55.0) (2026-10-05)


### Features

* **deps:** re-pin package-checker at v1.11.69 ([e88160a](https://github.com/maxgfr/ultrasec/commit/e88160a2925aca0182a27c996861afd01060eccd))

# [1.54.0](https://github.com/maxgfr/ultrasec/compare/v1.53.1...v1.54.0) (2026-10-04)


### Features

* **deps:** re-pin package-checker at v1.11.67 ([87ca469](https://github.com/maxgfr/ultrasec/commit/87ca469c3ac5822055ad7034dc6b61659b6b8abf))

## [1.53.1](https://github.com/maxgfr/ultrasec/compare/v1.53.0...v1.53.1) (2026-10-03)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([650f19d](https://github.com/maxgfr/ultrasec/commit/650f19ddf6486da82d1c3b01da4804eee9b25537))

# [1.53.0](https://github.com/maxgfr/ultrasec/compare/v1.52.1...v1.53.0) (2026-10-03)


### Features

* **deps:** re-pin package-checker at v1.11.65 ([7879873](https://github.com/maxgfr/ultrasec/commit/7879873ef3caebd797c4113afd6ea335e39e8657))

## [1.52.1](https://github.com/maxgfr/ultrasec/compare/v1.52.0...v1.52.1) (2026-10-02)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([7319529](https://github.com/maxgfr/ultrasec/commit/7319529eccfa2a1bd5a0075df381957e26e6e0fb))

# [1.52.0](https://github.com/maxgfr/ultrasec/compare/v1.51.1...v1.52.0) (2026-10-02)


### Features

* **deps:** re-pin package-checker at v1.11.63 ([57ca4d1](https://github.com/maxgfr/ultrasec/commit/57ca4d1fe92314669bc1e90d839d5ebbf4176fd3))

## [1.51.1](https://github.com/maxgfr/ultrasec/compare/v1.51.0...v1.51.1) (2026-10-01)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([bddb29d](https://github.com/maxgfr/ultrasec/commit/bddb29d2c19ec660738728337671f31995624cf7))

# [1.51.0](https://github.com/maxgfr/ultrasec/compare/v1.50.1...v1.51.0) (2026-10-01)


### Features

* **deps:** re-pin package-checker at v1.11.61 ([2e85ffe](https://github.com/maxgfr/ultrasec/commit/2e85ffed61853759d3d5da889501f94b34ed474a))

## [1.50.1](https://github.com/maxgfr/ultrasec/compare/v1.50.0...v1.50.1) (2026-10-01)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([0b556d9](https://github.com/maxgfr/ultrasec/commit/0b556d9e5f6bac4ad1e795fd6dbc2b5d1557d8db))

# [1.50.0](https://github.com/maxgfr/ultrasec/compare/v1.49.1...v1.50.0) (2026-09-30)


### Bug Fixes

* **catalog:** Python fetch() is a database call, not an SSRF sink ([ea12310](https://github.com/maxgfr/ultrasec/commit/ea12310d5ce892fbbd01c5e9f75a8a884525836e))
* **catalog:** treat Next.js "use server" modules as entry points ([cf5f0ef](https://github.com/maxgfr/ultrasec/commit/cf5f0eff6ae30675534fac7f2d966b7d09e7d06e))
* **guards:** search a handler's decorator block, not just its body ([6d3b82d](https://github.com/maxgfr/ultrasec/commit/6d3b82d90558aaa7ee6052de7d7e66e86845bbaf))


### Features

* **guards:** declare the project's own guard helpers as markers ([7acd4a2](https://github.com/maxgfr/ultrasec/commit/7acd4a23d45d35472020a4d856fc7d30978d360b))

## [1.49.1](https://github.com/maxgfr/ultrasec/compare/v1.49.0...v1.49.1) (2026-09-30)


### Bug Fixes

* adapt to the codeindex v2.31 resolve context and file-symlink walk ([f761c8e](https://github.com/maxgfr/ultrasec/commit/f761c8ec31b9e9ac89f77178a85e67e869196bff))

# [1.49.0](https://github.com/maxgfr/ultrasec/compare/v1.48.7...v1.49.0) (2026-09-30)


### Features

* **deps:** re-pin package-checker at v1.11.59 ([7c1f2b6](https://github.com/maxgfr/ultrasec/commit/7c1f2b6d321cf8e835fe8c979702f6add4c88b59))

## [1.48.7](https://github.com/maxgfr/ultrasec/compare/v1.48.6...v1.48.7) (2026-09-28)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([8d28fa7](https://github.com/maxgfr/ultrasec/commit/8d28fa71ddec40f22efc3267d14b068805bc3b86))

## [1.48.6](https://github.com/maxgfr/ultrasec/compare/v1.48.5...v1.48.6) (2026-09-14)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([e866c73](https://github.com/maxgfr/ultrasec/commit/e866c737d6a4a24a7da04e0989411c748230cbab))

## [1.48.5](https://github.com/maxgfr/ultrasec/compare/v1.48.4...v1.48.5) (2026-09-13)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([d45a4c7](https://github.com/maxgfr/ultrasec/commit/d45a4c7630403afdfc01d9fba8343408091a04f7))

## [1.48.4](https://github.com/maxgfr/ultrasec/compare/v1.48.3...v1.48.4) (2026-09-10)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([bf98048](https://github.com/maxgfr/ultrasec/commit/bf980481d277c3f791e2d33ae2de2017c1fd49ce))

## [1.48.3](https://github.com/maxgfr/ultrasec/compare/v1.48.2...v1.48.3) (2026-09-09)


### Bug Fixes

* **skills:** preserve manual invocation across agent hosts ([9ca4867](https://github.com/maxgfr/ultrasec/commit/9ca48676550c244e41597a2e4afc80f26040a1df))

## [1.48.2](https://github.com/maxgfr/ultrasec/compare/v1.48.1...v1.48.2) (2026-09-09)


### Bug Fixes

* **engine:** update shared engines and maintenance tool ([4eab6dc](https://github.com/maxgfr/ultrasec/commit/4eab6dc2ebe75df4ddbf5d4874e237fcf3bf8e3f))

## [1.48.1](https://github.com/maxgfr/ultrasec/compare/v1.48.0...v1.48.1) (2026-09-09)


### Bug Fixes

* reject malformed and duplicate persisted finding identities ([77aae93](https://github.com/maxgfr/ultrasec/commit/77aae93cb5e4660419706d17bf55baef5229b1bb))

# [1.48.0](https://github.com/maxgfr/ultrasec/compare/v1.47.3...v1.48.0) (2026-09-09)


### Features

* **deps:** re-pin package-checker at v1.11.55 ([b44ebd8](https://github.com/maxgfr/ultrasec/commit/b44ebd837dafd0340862e2e1c2315a75108e6b41))

## [1.47.3](https://github.com/maxgfr/ultrasec/compare/v1.47.2...v1.47.3) (2026-09-08)


### Bug Fixes

* **engine:** separate workflow maintenance from automatic repins ([5e27288](https://github.com/maxgfr/ultrasec/commit/5e27288cad26afe3352a0938a961c383938c0a40))

## [1.47.2](https://github.com/maxgfr/ultrasec/compare/v1.47.1...v1.47.2) (2026-09-08)


### Bug Fixes

* **engine:** unify pins, repins and shared engine adapters ([866627a](https://github.com/maxgfr/ultrasec/commit/866627a81135af6d391d225487002e6b6efda143))
* **engine:** unify pins, repins and shared engine adapters ([2dc3004](https://github.com/maxgfr/ultrasec/commit/2dc30044aaf3513418d281f66a5150e7c7acf24f))
* **engine:** unify pins, repins and shared engine adapters ([090158e](https://github.com/maxgfr/ultrasec/commit/090158ec4eb9bd1c47fdd5df52ffdc88145733e3))

## [1.47.1](https://github.com/maxgfr/ultrasec/compare/v1.47.0...v1.47.1) (2026-09-07)


### Bug Fixes

* retain partial scanner evidence and report all incomplete gates ([327c9e0](https://github.com/maxgfr/ultrasec/commit/327c9e0a7081ba6d365965044ac16c47b20c61a8))

# [1.47.0](https://github.com/maxgfr/ultrasec/compare/v1.46.0...v1.47.0) (2026-09-07)


### Features

* harden verification, add workflows and require explicit skill invocation ([d85c740](https://github.com/maxgfr/ultrasec/commit/d85c7402e2f994b2f998040e66c37450d40832e4))

# [1.46.0](https://github.com/maxgfr/ultrasec/compare/v1.45.1...v1.46.0) (2026-09-07)


### Features

* **engine:** re-pin vendored engines ([b5ffcdd](https://github.com/maxgfr/ultrasec/commit/b5ffcdd57a678cfa08baa7c73ec1eee6cc095b47))

## [1.45.1](https://github.com/maxgfr/ultrasec/compare/v1.45.0...v1.45.1) (2026-09-03)


### Bug Fixes

* harden MCP output and package checker runtime ([adce4e6](https://github.com/maxgfr/ultrasec/commit/adce4e68384a1e87a64c041b1a7410269eae73b9))
* **scanner:** prove safe crypto and rng identities ([d8b2758](https://github.com/maxgfr/ultrasec/commit/d8b275893885ed98585f999d18130c09f77ce9e2))

# [1.45.0](https://github.com/maxgfr/ultrasec/compare/v1.44.0...v1.45.0) (2026-09-03)


### Features

* **engine:** re-pin vendored engines ([9f68872](https://github.com/maxgfr/ultrasec/commit/9f68872f3cb50e7c57068dcdb68b3a44db69c961))

# [1.44.0](https://github.com/maxgfr/ultrasec/compare/v1.43.0...v1.44.0) (2026-09-03)


### Bug Fixes

* **hardening:** close four self-audit gaps and widen test-path demotion ([81c9688](https://github.com/maxgfr/ultrasec/commit/81c96883db3a41deba50b90af04a8ab9de620b24))


### Features

* **catalog:** Spring JdbcTemplate query methods are SQL sinks ([4139d70](https://github.com/maxgfr/ultrasec/commit/4139d7082c45c08d3aade33b7014714b4f0d12da))
* **catalog:** widen sink/source/sanitizer recall across JVM, Go, .NET, PHP and Ruby ([fecf52e](https://github.com/maxgfr/ultrasec/commit/fecf52eb201d494c2f3c08bb1eb70f6f385a163e))
* **config:** unpinned-action and token-permission vectors, app-hardening shapes ([5c7b3e6](https://github.com/maxgfr/ultrasec/commit/5c7b3e61eeb238dcd56f0f5dd72c17299c349ad9))


### Performance Improvements

* **scan:** one walk, shared file facts, indexed catalog — same output ([50dea2a](https://github.com/maxgfr/ultrasec/commit/50dea2a8e2bc15e2b3340b1f50a5ef6fcf191818))
* **tools:** run scanners in a pool and replay pure-function results under --resume ([a944974](https://github.com/maxgfr/ultrasec/commit/a944974f4a0a298a203d5805c4a28ac2a63ac88c))

# [1.43.0](https://github.com/maxgfr/ultrasec/compare/v1.42.0...v1.43.0) (2026-09-02)


### Features

* **engine:** re-pin vendored engines ([a74ad37](https://github.com/maxgfr/ultrasec/commit/a74ad371a0536b3cbf8c95b399eb2410c5e5851d))

# [1.42.0](https://github.com/maxgfr/ultrasec/compare/v1.41.2...v1.42.0) (2026-08-31)


### Features

* **engine:** re-pin vendored engines ([5ada809](https://github.com/maxgfr/ultrasec/commit/5ada8095352a039cb73d32f6e61b96f43ef6b817))

## [1.41.2](https://github.com/maxgfr/ultrasec/compare/v1.41.1...v1.41.2) (2026-08-25)


### Bug Fixes

* ship ultrasec maintainer references ([5c845f8](https://github.com/maxgfr/ultrasec/commit/5c845f8d4211ac0b129ce2ce4f9f56d992dbad25))

## [1.41.1](https://github.com/maxgfr/ultrasec/compare/v1.41.0...v1.41.1) (2026-08-25)


### Bug Fixes

* make ultrasec compatible with Codex ([17d43d7](https://github.com/maxgfr/ultrasec/commit/17d43d79980752b27d00840bce2ed3a6e45839f5))

# [1.41.0](https://github.com/maxgfr/ultrasec/compare/v1.40.2...v1.41.0) (2026-08-23)


### Bug Fixes

* **coverage:** four ASVS chapters could never leave "not examined" ([00feba0](https://github.com/maxgfr/ultrasec/commit/00feba06c236772e9cba13aff027a688e1fc3415))
* **report:** the surface split stopped at the undecided tier ([715d672](https://github.com/maxgfr/ultrasec/commit/715d672b662a0dd98263ec1193d1b90d2ad62f04))
* **scan:** --merge shipped two generations of noise rules side by side ([39fbd88](https://github.com/maxgfr/ultrasec/commit/39fbd88e91dc7be955231627af89509e7e6c329e))


### Features

* **report:** organise the audit by surface, and stop rendering dumps ([3722e51](https://github.com/maxgfr/ultrasec/commit/3722e5132eed8db3b81ff6a580165bab9c6d88be))

## [1.40.2](https://github.com/maxgfr/ultrasec/compare/v1.40.1...v1.40.2) (2026-08-23)


### Bug Fixes

* **sinks:** a class with no source to trace must not be gated on finding one ([980773a](https://github.com/maxgfr/ultrasec/commit/980773a128df6a0e5885031424d305b5ec8adaab))

## [1.40.1](https://github.com/maxgfr/ultrasec/compare/v1.40.0...v1.40.1) (2026-08-23)


### Bug Fixes

* **ci:** unblock the lint gate — a fixture placeholder, a schema drift, a format miss ([a8454a1](https://github.com/maxgfr/ultrasec/commit/a8454a1a774e6da3579d9071a29dc61742540b22))
* **graph:** a unique name is not a link, and four defects the re-audit found ([dba1a9f](https://github.com/maxgfr/ultrasec/commit/dba1a9fa9d0fc7b67646a0f9588698561a3b2ea5))

# [1.40.0](https://github.com/maxgfr/ultrasec/compare/v1.39.0...v1.40.0) (2026-08-22)


### Bug Fixes

* **noise:** a Jupyter checkpoint is a stale copy, like every other autosave ([ab75869](https://github.com/maxgfr/ultrasec/commit/ab75869cee2996b69a49d9eef29783be7fa26f01))
* **paths:** a kind it cannot list is not a kind that is absent ([dfbf26c](https://github.com/maxgfr/ultrasec/commit/dfbf26cc75236453558549c663063d985f778480))
* **run:** say it where the document is written, not only at the gate ([758bd7b](https://github.com/maxgfr/ultrasec/commit/758bd7bf2374d6c6b02438568bd6d4f050724556))


### Features

* **catalog:** the two ordinary classes a source→sink walk cannot shape ([49f9049](https://github.com/maxgfr/ultrasec/commit/49f904927315d7e42e57e168f19c61b359d033f1))
* **check:** confront CONTEXT.md's negations with the code ([b103aca](https://github.com/maxgfr/ultrasec/commit/b103acaf56c63be5db7ad428c567e0b207c629c9))
* **guards:** enumerate the OTHER absence — the rate limit nobody wrote ([0a78b48](https://github.com/maxgfr/ultrasec/commit/0a78b48c8100ffa7a17303e712a38eaf61e54db7))
* **run:** drive the throttle lens from the pipeline like every other stage ([165197f](https://github.com/maxgfr/ultrasec/commit/165197f84339bbfd417812a233eb13965e194672))
* **scan:** read the code that is stored as JSON ([afaea16](https://github.com/maxgfr/ultrasec/commit/afaea16fae40083be9dd550de15495784d33d866))


### Performance Improvements

* **notebooks:** count lines off the cursor that is already moving forward ([04e1c8b](https://github.com/maxgfr/ultrasec/commit/04e1c8b264409db0cb197eb08f16742c3d202f41))

# [1.39.0](https://github.com/maxgfr/ultrasec/compare/v1.38.0...v1.39.0) (2026-08-22)


### Bug Fixes

* **guards:** say "this app has no auth" once, not once per handler ([6b6483f](https://github.com/maxgfr/ultrasec/commit/6b6483fc649a2061dca54d4d83e6560bba6f56c5))
* **investigate:** keep the vulnerability class the auditor named ([b0a0804](https://github.com/maxgfr/ultrasec/commit/b0a0804b01e3b1d48c3aeda2c4c89131d00c858f)), closes [hi#severity](https://github.com/hi/issues/severity)
* **sinks:** give assignment sinks the orphan coverage calls always had ([e5293c7](https://github.com/maxgfr/ultrasec/commit/e5293c72cbaea132d308d5fb165d17818c56b316))
* **taint:** a test file is not an entry point ([d5876e9](https://github.com/maxgfr/ultrasec/commit/d5876e9386d54cc450c89ea8b5eb25cdc882a6cc))


### Features

* **authtokens:** report a password hash committed to the repository ([3caa2de](https://github.com/maxgfr/ultrasec/commit/3caa2de8afae5983c9a103e1582a73029a57db3e))

# [1.38.0](https://github.com/maxgfr/ultrasec/compare/v1.37.0...v1.38.0) (2026-08-21)


### Bug Fixes

* **catalog:** stop three rules answering a question they were not asked ([d7981bd](https://github.com/maxgfr/ultrasec/commit/d7981bd871d92f824723f2ebcd02a0837441b659)), closes [#13](https://github.com/maxgfr/ultrasec/issues/13)
* **check:** grade a history-scanned citation against its own commit, not HEAD ([1f3c631](https://github.com/maxgfr/ultrasec/commit/1f3c6311069ab98e420f32220032723f943079cc))
* **context:** detect the stack from declared workspaces, not only a depth-3 walk ([cdc892b](https://github.com/maxgfr/ultrasec/commit/cdc892b472de543eb00a1d4596ecdf5697b6b969)), closes [#11](https://github.com/maxgfr/ultrasec/issues/11)
* **context:** tell the shipped attack surface from the test harness in the brief ([d32827f](https://github.com/maxgfr/ultrasec/commit/d32827f574e240118b8aa7ed1fe92bfe3fa2466f)), closes [#12](https://github.com/maxgfr/ultrasec/issues/12)
* **dossier:** stop reprinting the whole trust model before every candidate ([fddc785](https://github.com/maxgfr/ultrasec/commit/fddc785f36ef4e5360b6cc1961ef67ea0fc569f7)), closes [#15](https://github.com/maxgfr/ultrasec/issues/15)
* **investigate:** fold a vulnerability-class name onto the category vocabulary ([7c9d987](https://github.com/maxgfr/ultrasec/commit/7c9d987431b7e0a892b2ea2c0a91206cd82c89a9))
* **noise:** classify history findings too, and group the families in DOSSIER.md ([1d815a3](https://github.com/maxgfr/ultrasec/commit/1d815a32aeae9c580b0d88e5bacb97e05cba9d40)), closes [#12](https://github.com/maxgfr/ultrasec/issues/12) [#12](https://github.com/maxgfr/ultrasec/issues/12) [#17](https://github.com/maxgfr/ultrasec/issues/17)
* **store:** stop --merge erasing the ground a refutation stands on ([537abf1](https://github.com/maxgfr/ultrasec/commit/537abf1955bcc2fce0d71dc22df21c7683033227))
* **verify:** emit a delta worklist, and never re-decide findings in silence ([a0f382f](https://github.com/maxgfr/ultrasec/commit/a0f382f2107ab15a0a8ff3cf3c422fd1194313bd)), closes [#14](https://github.com/maxgfr/ultrasec/issues/14)
* **verify:** make --apply idempotent instead of restating every verdict ([fbfca8b](https://github.com/maxgfr/ultrasec/commit/fbfca8ba7a1360146978209cabc4e640cf01f78c))


### Features

* **noise:** a document id is not a credential, and document the classes ([b115435](https://github.com/maxgfr/ultrasec/commit/b115435134da3e3ce174fcb193480047037b19d9)), closes [#17](https://github.com/maxgfr/ultrasec/issues/17)
* **noise:** a line that DESCRIBES a dangerous pattern is not a vulnerable site ([0f5c9b3](https://github.com/maxgfr/ultrasec/commit/0f5c9b31916c79eb611a432059449583df8c0a71))
* **scan:** de-prioritize noise by construction, and make the ground fillable ([3df413e](https://github.com/maxgfr/ultrasec/commit/3df413ecfd0a2f982dba3d91c55258c856848fd5)), closes [#12](https://github.com/maxgfr/ultrasec/issues/12) [#16](https://github.com/maxgfr/ultrasec/issues/16) [#17](https://github.com/maxgfr/ultrasec/issues/17)
* **taint:** show whether the value ARRIVES, and let the reader decide ([ae50d4a](https://github.com/maxgfr/ultrasec/commit/ae50d4a19dfbdb0ab43c1fe693913c10a3b8261d)), closes [#13](https://github.com/maxgfr/ultrasec/issues/13) [#13](https://github.com/maxgfr/ultrasec/issues/13)

# [1.37.0](https://github.com/maxgfr/ultrasec/compare/v1.36.0...v1.37.0) (2026-08-21)


### Bug Fixes

* **catalog:** corroborate ambiguous command callees before firing CWE-78 ([adac6f5](https://github.com/maxgfr/ultrasec/commit/adac6f5468d58d0f20d3a2e84c428aa2f0cf237b)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **catalog:** match requireModule case-insensitively, and correct the record ([d1fb3d3](https://github.com/maxgfr/ultrasec/commit/d1fb3d3fa185c481452ed4a3e4a51ad9667c1029)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **context:** rank the entry-point brief by surface, and stop capping by alphabet ([8d9e7dd](https://github.com/maxgfr/ultrasec/commit/8d9e7ddc58638cee8ac524ac5cae51c411c7fa6b)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **coverage:** score logging coverage from the CWEs present, not the pass ([4b3dabe](https://github.com/maxgfr/ultrasec/commit/4b3dabea9dd1c3edbe8bcb1fa4bddb890d136545)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **scope:** make --gitignore mean one thing across the whole run ([bfb81b2](https://github.com/maxgfr/ultrasec/commit/bfb81b25b4eb4e1e9f35dc4bde7772c436dbd835)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)


### Features

* **context:** find entry points by convention and signature, not only by content ([a5a95eb](https://github.com/maxgfr/ultrasec/commit/a5a95ebc3b649e7f8cabc155a4135c0519830731)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **scan:** report progress on stderr instead of running silently ([479b29f](https://github.com/maxgfr/ultrasec/commit/479b29f1f0f563ff19f50530acd800703f6d7a48)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)
* **secrets:** de-prioritize ciphertext-by-design, and catch templated credential URIs ([b6e731f](https://github.com/maxgfr/ultrasec/commit/b6e731f1941bce9020412bc18d142bfa73011a98)), closes [#10](https://github.com/maxgfr/ultrasec/issues/10)

# [1.36.0](https://github.com/maxgfr/ultrasec/compare/v1.35.0...v1.36.0) (2026-08-19)


### Features

* **deps:** re-pin package-checker at v1.11.54 ([26e9366](https://github.com/maxgfr/ultrasec/commit/26e93660286820ba0a685d998b4b9f80bab88bf2))

# [1.35.0](https://github.com/maxgfr/ultrasec/compare/v1.34.0...v1.35.0) (2026-08-18)


### Features

* **deps:** re-pin package-checker at v1.11.53 ([3ba6a81](https://github.com/maxgfr/ultrasec/commit/3ba6a812c66e245490978ba2732d13ff53af6359))

# [1.34.0](https://github.com/maxgfr/ultrasec/compare/v1.33.0...v1.34.0) (2026-08-17)


### Features

* **deps:** re-pin package-checker at v1.11.51 ([6301eb4](https://github.com/maxgfr/ultrasec/commit/6301eb4f0ff97a248beb9c9970d68f9ee858cfad))

# [1.33.0](https://github.com/maxgfr/ultrasec/compare/v1.32.0...v1.33.0) (2026-08-16)


### Features

* **deps:** re-pin package-checker at v1.11.50 ([55a4585](https://github.com/maxgfr/ultrasec/commit/55a4585c36c4bbde2797bca714c592c5bcb29b9d))

# [1.32.0](https://github.com/maxgfr/ultrasec/compare/v1.31.0...v1.32.0) (2026-08-15)


### Features

* **deps:** re-pin package-checker at v1.11.48 ([bdad6de](https://github.com/maxgfr/ultrasec/commit/bdad6de6a14f9000f09d688440812c754da3ba22))

# [1.31.0](https://github.com/maxgfr/ultrasec/compare/v1.30.0...v1.31.0) (2026-08-14)


### Features

* **deps:** re-pin package-checker at v1.11.46 ([634701b](https://github.com/maxgfr/ultrasec/commit/634701b684707c866a28afeb7a970761e099cd27))

# [1.30.0](https://github.com/maxgfr/ultrasec/compare/v1.29.0...v1.30.0) (2026-08-13)


### Features

* **engine:** re-pin vendored engines ([48d48e1](https://github.com/maxgfr/ultrasec/commit/48d48e16169c2fe330a47c218674a2d7b68b8e0d))

# [1.29.0](https://github.com/maxgfr/ultrasec/compare/v1.28.0...v1.29.0) (2026-08-13)


### Features

* **deps:** re-pin package-checker at v1.11.44 ([326a9af](https://github.com/maxgfr/ultrasec/commit/326a9af2f2763b8a1193e0b037a75b4f38a32cab))

# [1.28.0](https://github.com/maxgfr/ultrasec/compare/v1.27.0...v1.28.0) (2026-08-12)


### Features

* **deps:** re-pin package-checker at v1.11.42 ([5b9e1dc](https://github.com/maxgfr/ultrasec/commit/5b9e1dca0a24a0ca33670e8e705145995ef0947c))

# [1.27.0](https://github.com/maxgfr/ultrasec/compare/v1.26.1...v1.27.0) (2026-08-11)


### Features

* **deps:** re-pin package-checker at v1.11.40 ([2f1b42f](https://github.com/maxgfr/ultrasec/commit/2f1b42f26942f9f121b63bd4cc4b15425b728b65))

## [1.26.1](https://github.com/maxgfr/ultrasec/compare/v1.26.0...v1.26.1) (2026-08-10)


### Bug Fixes

* **build:** keep the example audit reproducible when the fixture has node_modules ([01b7fe8](https://github.com/maxgfr/ultrasec/commit/01b7fe85356c20b3c2da6efc8be8fd065f556baf))
* **deps:** patch the five open Dependabot advisories ([470a8ed](https://github.com/maxgfr/ultrasec/commit/470a8edf5e277ef4979bd9287ac5711738011943))

# [1.26.0](https://github.com/maxgfr/ultrasec/compare/v1.25.1...v1.26.0) (2026-08-10)


### Features

* **deps:** re-pin package-checker at v1.11.39 ([bfb958f](https://github.com/maxgfr/ultrasec/commit/bfb958f76679ce9f512fe16c44b43ca0cbcbef39))

## [1.25.1](https://github.com/maxgfr/ultrasec/compare/v1.25.0...v1.25.1) (2026-08-10)


### Bug Fixes

* **ci:** push the package-checker re-pin to main instead of opening a PR ([bf50a8c](https://github.com/maxgfr/ultrasec/commit/bf50a8cb2e07c35951c8d323cd48b87dd8839d4e))

# [1.25.0](https://github.com/maxgfr/ultrasec/compare/v1.24.0...v1.25.0) (2026-08-10)


### Features

* **deps:** re-pin package-checker at v1.11.38 ([44d840c](https://github.com/maxgfr/ultrasec/commit/44d840c4314ce1da92fc01352851cc2551789389))

# [1.24.0](https://github.com/maxgfr/ultrasec/compare/v1.23.0...v1.24.0) (2026-08-10)


### Bug Fixes

* **ci:** regenerate the goldens on an engine re-pin, guarded against recall loss ([a8c2768](https://github.com/maxgfr/ultrasec/commit/a8c2768b73034e1b98835a436f27312e3963dfc3))


### Features

* **engine:** re-pin codeindex v2.27.1 ([0e9ddd2](https://github.com/maxgfr/ultrasec/commit/0e9ddd2b29e78d78a44c760c9cad337625588eb8))

# [1.23.0](https://github.com/maxgfr/ultrasec/compare/v1.22.1...v1.23.0) (2026-08-10)


### Features

* config/auth/cloud detectors, standards packs, live-site probe and out-of-scope triage ([fb567d8](https://github.com/maxgfr/ultrasec/commit/fb567d811ea4b57e379c81940f06a188d393340f))

## [1.22.1](https://github.com/maxgfr/ultrasec/compare/v1.22.0...v1.22.1) (2026-08-06)


### Bug Fixes

* **ci:** regenerate the example audit during an engine re-pin ([#8](https://github.com/maxgfr/ultrasec/issues/8)) ([78f7b44](https://github.com/maxgfr/ultrasec/commit/78f7b443296c26486df57ff7fcbaad9309594e89))

# [1.22.0](https://github.com/maxgfr/ultrasec/compare/v1.21.0...v1.22.0) (2026-08-06)


### Features

* **engine:** measure detection on a public corpus, then fix what it exposed ([#7](https://github.com/maxgfr/ultrasec/issues/7)) ([c33ad7c](https://github.com/maxgfr/ultrasec/commit/c33ad7c2b2b73647343ea589c67e2c60f33744b5))

# [1.21.0](https://github.com/maxgfr/ultrasec/compare/v1.20.0...v1.21.0) (2026-08-03)


### Features

* **skill:** release the apply-loss fix, monorepo lockfiles and the privacy dimension ([d190d43](https://github.com/maxgfr/ultrasec/commit/d190d43dc17d683ba1c712d0c7bbd9c1e3c356f1)), closes [#6](https://github.com/maxgfr/ultrasec/issues/6)

# [1.20.0](https://github.com/maxgfr/ultrasec/compare/v1.19.0...v1.20.0) (2026-07-29)


### Features

* **mcp:** serve ultrasec over the Model Context Protocol ([fe63983](https://github.com/maxgfr/ultrasec/commit/fe63983fc5a640ae454e6df7efb530757422be22))

# [1.19.0](https://github.com/maxgfr/ultrasec/compare/v1.18.0...v1.19.0) (2026-07-26)


### Features

* **engine:** re-pin codeindex v2.20.1 ([bf49cf7](https://github.com/maxgfr/ultrasec/commit/bf49cf7d2db59dda6746285acc9bc847af1aeeeb))

# [1.18.0](https://github.com/maxgfr/ultrasec/compare/v1.17.0...v1.18.0) (2026-07-25)


### Bug Fixes

* **cli:** fail closed everywhere a run used to degrade in silence ([19a9d6a](https://github.com/maxgfr/ultrasec/commit/19a9d6a2af8c36ff672b6dcc5c5202d299338ea6))


### Features

* **skill:** rewrite ultrasec as a security reference, not a CLI manual ([85b11d0](https://github.com/maxgfr/ultrasec/commit/85b11d0b5c00c66d7abd409a09259f30b72377c9))

# [1.17.0](https://github.com/maxgfr/ultrasec/compare/v1.16.1...v1.17.0) (2026-07-25)


### Features

* **engine:** re-pin codeindex v2.17.0 ([0301b7c](https://github.com/maxgfr/ultrasec/commit/0301b7c4196a1f6524e5514ec27d694bd01748d9))

## [1.16.1](https://github.com/maxgfr/ultrasec/compare/v1.16.0...v1.16.1) (2026-07-24)


### Bug Fixes

* **scan:** warm the tree-sitter grammars — the AST tier was never reachable ([9048ffe](https://github.com/maxgfr/ultrasec/commit/9048ffef7dff89b3d0013df015c871e0cb9e79b0))

# [1.16.0](https://github.com/maxgfr/ultrasec/compare/v1.15.0...v1.16.0) (2026-07-24)


### Features

* **engine:** re-pin codeindex v2.15.0 ([f4d3b27](https://github.com/maxgfr/ultrasec/commit/f4d3b27c2ba86a56fefcc9eb878ef220a99407c8))

# [1.15.0](https://github.com/maxgfr/ultrasec/compare/v1.14.0...v1.15.0) (2026-07-24)


### Features

* **engine:** re-pin codeindex v2.14.0 ([c257a38](https://github.com/maxgfr/ultrasec/commit/c257a385762f0829782fe4de5dfcbc482a0de468))

# [1.14.0](https://github.com/maxgfr/ultrasec/compare/v1.13.0...v1.14.0) (2026-07-24)


### Features

* **engine:** re-pin codeindex v2.13.0 ([a3be8cb](https://github.com/maxgfr/ultrasec/commit/a3be8cba3512fbff3d4a34a68e7567ba63e397c5))

# [1.13.0](https://github.com/maxgfr/ultrasec/compare/v1.12.0...v1.13.0) (2026-07-23)


### Bug Fixes

* **ci:** fully vet auto-bump PRs since the default token can't trigger ci.yml ([0a0f5c2](https://github.com/maxgfr/ultrasec/commit/0a0f5c276999ca0257eaee1b2ac13cd6ed9741db))
* **docker:** resolve hadolint's post-2.13 asset rename for pinned versions ([8b05576](https://github.com/maxgfr/ultrasec/commit/8b0557639719239990c6603a540658c6ce788192))


### Features

* **docker:** install toolbox scanners at latest by default ([92f2c2e](https://github.com/maxgfr/ultrasec/commit/92f2c2e974dbb24c403ecabf0a9ef9579151a2b5))
* **docker:** track latest tags for docker-mode scanner images ([42ad220](https://github.com/maxgfr/ultrasec/commit/42ad220a0548077d85680a55dc0debf67657ea43))
* **package-checker:** resolve upstream latest with vendored fallback ([11061e1](https://github.com/maxgfr/ultrasec/commit/11061e11717c4c9d5b0e6b1bb0ec2413f865c2bc))
* **tools:** infer native-tool origin and drive `tools --upgrade` ([86baab9](https://github.com/maxgfr/ultrasec/commit/86baab9b4a165ed7da10d4597b9d281119df0f35))

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
