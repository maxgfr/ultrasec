# Taint catalog & CWE coverage

The catalog (`src/catalog.ts`) is the deterministic half of taint enumeration:
**sources** (untrusted input), **sinks** (dangerous operations), and
**sanitizers** (neutralizers). It is recall-oriented — a spurious candidate costs
you a glance; a missed flow is a missed bug.

## Sinks → CWE

| kind | CWE | severity | example callees |
|------|-----|----------|-----------------|
| sql | CWE-89 | high | `query`, `execute`, `raw`, `executemany` · JDBC/JPA: `prepareStatement`, `prepareCall`, `executeUpdate`, `addBatch`, `createQuery` · Go `db.Query|QueryRow|Exec|*Context` (receiver-gated) · PHP `mysqli_query`, `pg_query`, `mysqli_prepare` · Rails `Model.where|order|pluck|find_by_sql` (receiver-gated) |
| nosql | CWE-943 | high | `db.find`, `collection.findOne`, `mapReduce`, `aggregate` (receiver-gated) |
| command | CWE-78 | critical | `execSync`, `spawnSync`, `popen`, `Popen`, `shell_exec`, `passthru`, `proc_open`, `ProcessBuilder`, `Runtime.getRuntime` · plus `exec`/`spawn`/`run` **corroborated** (see below) |
| code | CWE-94 | high | `eval`, `Function`, `runInThisContext`, `compile` · PHP `create_function`, `assert($x)` (line shape) · Ruby `instance_eval|class_eval|module_eval|*_exec` · plus the **line shape** `.apply(eval)` / `.map(exec)`, where the interpreter is a *reference*, not a call |
| ssti | CWE-1336 | high | `from_string`, `renderString`, `Template`, `compileString` · JVM `Velocity.evaluate`, `template.process|merge` (receiver- + import-gated) |
| path | CWE-22 | high | `readFile`, `writeFile`, `sendFile`, `send_from_directory`, `open` · JVM/C# constructors: `new File`, `FileInputStream`, `newBufferedReader` · Go `os.Open|ReadFile|WriteFile|Create` · PHP `fopen`, `file_get_contents`, `file_put_contents`, `readfile` · Ruby `File.read|IO.readlines|FileUtils.*` · Python `shutil.copy|move|rmtree` · zip-slip: `extractall`, `extract`, `unzip` |
| include | CWE-98 | high | PHP `include`/`require`/`*_once` — call form, plus the **keyword form** `require $page;` as a line shape (a literal argument never matches) |
| ssrf | CWE-918 | high | bare `fetch`, `request`, `urlopen`, `axios`, `got` · + member calls `axios.get`, `http.get`, `requests.get`, `session.post` (receiver-gated) · JVM `restTemplate.getForObject|exchange`, `httpClient.execute|send`, `url.openStream` (receiver- + import-gated) · PHP `curl_init`, `curl_setopt`, `curl_exec` · Ruby `Net::HTTP.get`, `Faraday|RestClient|HTTParty.get`, `URI.open` |
| xxe | CWE-611 | high | `parseString`, `parseFromString`, `fromstring`, `SAXParser`, `DocumentBuilder` · PHP `simplexml_load_string|file`, `loadXML`, `loadHTML` |
| ldap | CWE-90 | high | `ldap.search`, `client.bind` (receiver-gated) · JVM `ctx|ic|dirContext.search|bind` |
| xss | CWE-79 | medium | `res.send`, `res.write`, `w.Write`, `render_template_string` · JVM servlet writers: `println`, `print`, `write`, chained `format` (import-gated) · Go `fmt.Fprintf|Fprint`, `io.WriteString`, and `template.HTML|JS|URL` (escaping bypass, high) · ASP.NET `Response.Write|WriteAsync` |
| crlf | CWE-93 | medium | `res.setHeader`, `res.header`, `addHeader` (receiver-gated) |
| proto | CWE-1321 | high | `_.merge`, `_.defaultsDeep`, `extend` (receiver-gated) |
| deserialize | CWE-502 | high | `pickle.loads`, `yaml.load`, `unserialize`, `readObject` · .NET `BinaryFormatter|SoapFormatter|LosFormatter|JavaScriptSerializer.Deserialize`, `JsonConvert.DeserializeObject` (receiver-gated) |
| crypto | CWE-327 | medium | `md5`, `sha1`, `createCipher`, `DES` · JVM: `MessageDigest.getInstance`, `Cipher.getInstance` (receiver-gated; read the algorithm string) · Go `md5|sha1.New|Sum` (CWE-328), `des|rc4.NewCipher` |
| redirect | CWE-601 | medium | `res.redirect`, `window.open` · JVM `response.sendRedirect` · Go `http.Redirect` · ASP.NET `Response.Redirect`, bare `Redirect(returnUrl)`, `RedirectToAction` |
| buffer | CWE-120 | high | C/C++ best-effort: `strcpy`, `strcat`, `sprintf`, `gets`, `memcpy` |
| argv | CWE-88 | high | `execFile`, `execFileSync`, `execve`, `posix_spawn` |
| domxss | CWE-79 | high | **assignments**, not calls: `.innerHTML =`, `dangerouslySetInnerHTML`, `v-html`, `.src =` |
| llm | CWE-1427 | high | `completions.create`, `messages.create`, `chain.invoke`, `model.generate` (receiver- + import-gated) |
| redos | CWE-1333 | medium | `new RegExp`, `regexp.MustCompile`, `re.compile` (receiver-gated) |
| algodos | CWE-407 | medium | `fuzz.extract`, `ratio`, `token_sort_ratio`, `distance`, `levenshtein`, `findBestMatch`, `get_close_matches` (import-gated) |
| errleak | CWE-209 | low | **line shape**, not a call: `res.json({ error: err.message })`, `NextResponse.json({ message: String(error) })`, `jsonify({"error": str(e)})` |
| reflect | CWE-470 | medium | `getattr`, `Class.forName`, `importlib.import_module`, `newInstance` · Ruby `obj.send|public_send|const_get` (receiver-gated) |
| xpath | CWE-643 | high | `selectNodes`, `xpath.select`, `xpath.compile`, `evaluate` (receiver-gated; `compile` is claimed here BEFORE the `code` rule can) |
| massassign | CWE-915 | medium | `setAttributes`, `bulkCreate`, `fill`, `update_attributes` |
| csv | CWE-1236 | medium | `writerow`, `to_csv`, `fputcsv`, `writeRecords` |
| trustboundary | CWE-501 | medium | `session.setAttribute`, `putValue` (JVM) |
| cookie | CWE-614 | medium | `addCookie` — read Secure/HttpOnly/SameSite in the dossier |
| random | CWE-330 | low | `Math.random`, `new Random`, `nextInt`, `randint` (receiver-gated) |

Coverage per language is uneven, and the numbers say where: the JVM rows above exist because
`pnpm bench:public` measured **0% detection** on OWASP Benchmark for command injection, XSS, path
traversal and weak crypto — the self-written fixtures had all scored 100% and hidden it. See
[`BENCHMARK.md`](BENCHMARK.md).

Three of these deserve a word.

**`exec` and `run` are corroborated before they fire.** They are among the most reused identifiers
in programming, and the extractor reports a receiver only when it is a plain identifier — so
`/(LEGIARTI\w+)/.exec(url)`, `pool.exec()` and a genuinely bare `exec()` all reach the matcher
looking the same. A single name-matching rule therefore rated `RegExp.prototype.exec` as CRITICAL
OS command injection; on a repo that parses legal-document ids with regexes that was 11 of 17
criticals, plus a 12th on an application `run()` declared 68 lines above its own call site.

So the ambiguous names now need corroboration — a known receiver (`child_process.exec`,
`subprocess.run`, `exec.Command`) or a process-module import (`child_process`, `execa`, `shelljs`,
`subprocess`, `os/exec`, `std::process`), which is what catches `from subprocess import run`. A
callee the file **declares itself** never matches: shadowing is a language rule, and it outranks
the import. PHP keeps firing bare, because PHP's process builtins have no receiver to resolve.

When the extractor could not see imports **at all** — the regex tier — the candidate is not
dropped, it is reported at **medium** carrying `unresolved-receiver` in its message. A critical we
cannot substantiate is worse than a medium we can revisit; silently losing a real sink because
tree-sitter was missing would be worse than both.

**`argv` (CWE-88) exists because the `command` sanitizer hint is only half a defence.** Moving off a
shell string onto an argv array kills metacharacter injection and nothing else: an attacker who
controls an *argument* still gets code execution out of plenty of ordinary binaries —
`git --upload-pack=`, `curl -o`, `ssh -oProxyCommand=`, `tar --checkpoint-action=`, `rsync -e`.
So `execFile` is a sink in its own right, not a safe harbour. Ask whether the value can begin with
`-`, and whether the callee has an option that runs something.

**`domxss` is matched as an ASSIGNMENT.** `el.innerHTML = userInput` is the commonest DOM XSS shape
in the wild and it is not a call at all, so a call-based catalog could never see it. These rules run
over the line text, like sources do.

**`algodos` (CWE-407) is ReDoS's sibling, and the cost lives in someone else's code.** The
super-linear blow-up is not in a pattern the caller wrote, it is inside the library the caller
called: `fuzz.extract(userQuery, tenThousandVariants)` is an O(n·m) Levenshtein DP, synchronous, no
early exit. Measured on a real audit, the taint walk already had the whole path — query → controller
→ service → this call — and emitted nothing, because the catalog had no sink at the end of it. It is
import-gated for the usual reason (`extract`, `ratio`, `distance` and `similarity` are ordinary
method names), and its sanitizer looks for an upper **bound**, never for validation. That distinction
is the whole finding: the audited repo validated every parameter with zod, `min(1)`, no `max`, and
shipped a remote CPU denial of service. So the general "type-coercion/validation present" hint is
suppressed for this kind — on this class it would tell you the opposite of the truth.

**`errleak` (CWE-209) has no untrusted source, which is why nothing found it.** The tainted value is
the *exception*, produced by the server, so no source→sink walk can reach this class however deep it
goes. It is a line shape instead — the response writer and the error expression on one line — and
the gap between them forbids `)`, so `const d = await res.json(); log(err.message)` (two unrelated
statements) does not match while `res.status(500).json({ error: err.message })` does. Rated `low` on
purpose: what it leaks is usually a driver name or a status text, and it is the adjudicator who
raises it when the message carries a stack, a SQL fragment or an internal hostname.

**`llm` (CWE-1427) runs in both directions**, and the second one is the severe one:

- *into* the model — untrusted input concatenated into a prompt (the sink above);
- *out of* the model — a completion is a `llm`-kind **source**, because anything the model read
  (a RAG document, a fetched page, a tool result) can steer what it writes. When that output reaches
  `exec`/SQL/the filesystem, the prompt boundary is the only thing between a web page and your shell.

The only control that holds for this class is constraining what the output is *allowed to do*
(schema, tool allow-list) — prompt-level "sanitizing" does not survive contact with a real attacker,
and the sanitizer hint says so.

> **The severity column is a starting prior, not a verdict.** It says how bad this class *usually*
> is, with no knowledge of your app. Stored XSS in an admin panel outranks the `medium` shown
> here; `md5` used for an ETag is not a finding at all. Rate what you confirm with
> [severity-and-discipline.md](severity-and-discipline.md), which carries worked pairs for
> exactly these cases.

Receiver-gated rules only match when the call's receiver is in a known set (e.g.
`db`/`collection`/`Model` for NoSQL, an HTTP client for SSRF member calls) so common
look-alikes (`Array.prototype.find`, a plain `merge()`, a `cache.get()`) don't flood
the candidate list. The SSRF member-call rule additionally *requires* a receiver, so
a bare `get(x)` never matches. Coverage is deepest for the web stacks; `buffer` is a
best-effort C/C++ scaffold — pair it with cppcheck/gosec.

Every class above is exercised by a labelled per-CWE benchmark (`tests/fixtures/bench/`, 28
classes, with Java/Go/C#/PHP/Ruby/Python twins wherever a rule is language-specific), scored by
`tests/bench.test.ts` for per-class TPR/FPR/Youden against a safe twin that
must not be flagged — by ANY rule, not merely its own, so a new rule cannot buy recall with
cross-class noise. A CI gate against class-specific detection regressions.

## Sources

**Server request input** — Express/Koa (`req.query/body/params/headers/files`, `ctx.*`), Flask &
Django (`request.args/form/GET/POST`), Starlette/FastAPI (`request.query_params`, `Query()`,
`Body()`, `Form()`), PHP superglobals and Laravel/Symfony (`$request->input|query|all`), servlets
**and Spring** (`@RequestParam`, `@PathVariable`, `@RequestBody`), Ktor (`call.receive`), ASP.NET
(`Request.Query|Form|Headers`, `[FromBody]`), Rails `params`, Go `net/http` **plus gin/echo/fiber**
(`c.Param|Query|ShouldBind`) and gorilla/chi route params, Rust axum/actix extractors (`Query<T>`,
`Path<T>`, `Json<T>`), Phoenix (`conn.params`), NestJS decorators (`@Body`, `@Query`), Next.js
(`searchParams.get`, `await req.json()`), Hono (`c.req.query|param|json`), tRPC/oRPC (`.input(schema)`),
GraphQL resolvers (`(parent, args)`), Spring mappings (`@GetMapping`…), Django REST framework
(`@api_view`, `APIView`), Vapor/Swift. **By convention** (the path, not the content): Next/Nuxt/SvelteKit
route files, serverless handlers, `*Controller` files, Django `views.py`, PHP web roots — and the
route tables themselves, Laravel `routes/web.php|api.php` (`Route::get(...)`) and Rails
`config/routes.rb` (`get "/x", to: ...`).

**Client-side (DOM)** — `location.hash|search|href`, `document.URL|referrer|cookie`, `window.name`,
`URLSearchParams`, `localStorage/sessionStorage.getItem`, `history.state`, and `event.data` from a
`message` listener (cross-origin; a listener with no `event.origin` check is CWE-346 on its own).

**Model output** — a completion, a LangChain `.invoke/.run`, `generate_content`. Attacker-*influenced*
rather than attacker-typed, and the reason the `llm` class runs in both directions.

**Everything else** — WebSocket/stream messages (`.on("message"…)`), CLI args (`process.argv`,
`sys.argv`, `os.Args`, `env::args`, shell `$1`/`$@`, `read`), env (`process.env`, `os.environ`,
`getenv`), stdin (`input()`).

> The framework rules matter more than they look. Before them, a Spring Boot, ASP.NET, Actix or
> Phoenix repo produced a link-graph and almost **no entry surface** — the engine came back clean by
> default of detection, which is the worst way for it to be wrong.

## Sanitizers (hints)

Parameterized queries (`?`/`$1`/`:name` placeholders, and the **binding calls** that follow a
prepare — `setString`, `bind_param`, `bindValue`, PDO `execute([...])`, `encodeForSQL`, the hash
form of Rails `where`), shell quoting
(`shlex.quote`, `escapeshellarg`, `execa`, `shell-quote` — note that argv-array exec neutralizes CWE-78 and
raises CWE-88, so it annotates `command` and is itself the `argv` sink), path confinement (`basename`,
`realpath`, `secure_filename`), HTML escaping (`escapeHtml`, `DOMPurify`,
`bleach`, `markupsafe`, and the JVM/.NET/Go encoders: ESAPI `encodeForHTML`, OWASP `Encode.forHtml`,
`HtmlUtils.htmlEscape`, `HttpUtility.HtmlEncode`, `html.EscapeString`, `htmlspecialchars`), safe loaders
(`yaml.safe_load`, `JSON.parse`), NoSQL operator-stripping (`mongo-sanitize`), XML entity-disabling
(`resolve_entities=False`, `FEATURE_SECURE_PROCESSING`), LDAP escaping
(`ldap.escape`, `encodeForLDAP`, `encodeForDN`), redirect/SSRF destination checks (`new URL(x)`,
`url_has_allowed_host_and_scheme`, `IsLocalUrl`, an `allowedHosts` set), CR/LF stripping,
prototype-pollution guards (`Object.create(null)`, `__proto__` checks), template autoescaping /
sandboxing, and type-coercion/validation (`parseInt`, `Number`, `validator.*`, `zod`/`Joi`/`yup`/`ajv`,
express-validator `body()`/`check()`, `class-validator`, `pydantic`, `marshmallow`, `@Valid`), and an
input-length **bound** (`slice(0, n)`, `max(n)`, `maxLength`, `[:n]`) for `algodos`. The sink line, the
three lines above it AND the three below it are inspected, because a prepared statement binds its
parameters after the prepare. These **lower confidence and annotate** a candidate — they do not
auto-dismiss it; you confirm the sanitizer actually covers the flow.

One rule opts out of the general one, and the exception is the point: `algodos` never receives the
"type-coercion/validation present" hint. A schema that checks the *type* says nothing about the
*length*, and the repo that produced this class had zod on every route — with `min(1)` and no `max`.
On that line the general hint would have handed the adjudicator the exact reassurance the bug
depends on. A floor is not a bound.

## Two signals that sharpen a candidate

Enumeration is structural: a source at-or-above the sink's frame in the same file closes a path.
Two per-candidate fields say how much that co-occurrence is worth, and neither filters anything:

- **`sourceScope`** — `symbol` (source and sink in ONE function) · `module` (source at file scope,
  e.g. a middleware) · `file` (source in a *different* function of the same file — co-location and
  nothing more). Recovered from the code's block structure, not the symbol table, because the case
  that matters most has no symbols: an Express router extracts **zero** of them, every handler
  being an anonymous arrow. `scan --strict-scope` drops the `file` tier when you want a shorter
  queue — but prefer READING the evidence over dropping it: every dossier now carries a
  **Reachability evidence** block stating the scope tier, the def-use verdict, the bindings the
  walk followed, and (for an assignment sink) whether any of them appear in the assigned value.
  That answers the same question per candidate instead of discarding a whole tier, and a value
  *can* travel between two functions through module state.
- **`dataflow`** — `linked` (a def-use walk still sees the source's bound value at the sink) ·
  `unlinked` (it looked and the binding is never mentioned again) · *absent* (undecidable — inline
  use, an object, a template). **Absent is not `unlinked`**: only claim the value fails to arrive
  when the walk actually said so.

Ranking is severity → scope → `unlinked` last → proximity → cross-file, so the `dossier` reads you
pay for land on the flows most likely to be real.

## Extraction tier changes what gets enumerated

Symbols and call sites come from tree-sitter when the grammars are available and from regex
extractors when they aren't. The dossier records which ran, in `manifest.extraction`. This is not
a detail: measured on a 69-file TypeScript repo, the regex tier produced **27 taint candidates
instead of 66**, lost every cross-file command-injection candidate, and dropped two CWE classes
entirely. `ast: false` means the catalog below was applied to a thinner view of the code — check
it before concluding a class is absent, and say so in the report.

## Jupyter notebooks are scanned as Python

A `.ipynb` is JSON, so for a long time nothing in this engine read one — and no external scanner
does either: bandit has had B307 (`eval`) forever and simply cannot open the format. On a repo with
eight notebooks that produced the two statements a security tool must never both make: eight files
tracked, nothing in them.

`scan` now extracts each notebook's code cells into a **line-aligned Python shadow** — line N of the
shadow is line N of the raw JSON — runs the ordinary extractor over it, and files the result under
the notebook's own path. So a notebook is an ordinary scanned file to the taint walk, the orphan-sink
layer, the graph and `coverage`, and every citation it produces resolves in the file a reader opens.

What the run tells you, and why each number is there:

- `notebooks: 8/8 .ipynb extracted as python` — found vs. actually read.
- `N checkpoint copy(ies) skipped` — `.ipynb_checkpoints/` is Jupyter's autosave. Scanning it
  doubles every finding in the tree.
- `N source line(s) could not be aligned and are NOT cited` — a cell whose `source` is one
  multi-line string puts all its lines on a single raw line. Those are counted, never guessed at.

Two limits worth knowing. Magics (`%matplotlib`) and shell escapes (`!pip …`) are blanked, because
they are not Python — the line still exists, so nothing after it shifts. And the line-content passes
(sanitizer hints, secret scanning, the `dossier` excerpt) read the raw JSON line, which carries the
cell's source text: readable, correctly numbered, JSON-escaped.

## Beyond taint: config & auth line-detectors (run under `scan`)

Some classes have no source→sink flow — the bug is a value that is wrong on its own line. Two
line-oriented detectors run automatically under `ultrasec scan` and emit grounded `[file:line]`
candidates (`category: config`/`authz`/`crypto`), correlated with the scanners like any other:

- **Web misconfiguration** (`src/webconfig.ts`) — permissive/reflected CORS (CWE-942); cookies set
  without HttpOnly/Secure/SameSite (CWE-1004/614/1275); security headers set to unsafe values (CSP
  `unsafe-inline`/`unsafe-eval`, `X-Frame-Options: ALLOWALL`, HSTS `max-age=0`, `Referrer-Policy:
  unsafe-url`); TLS certificate verification disabled (CWE-295 — Node/Python/Go/PHP/Java);
  framework debug mode (CWE-489); directory listing (CWE-548); GraphQL introspection (CWE-200);
  **CSRF guard switched off** (CWE-352 — a commented-out `protect_from_forgery`, a
  `skip_before_action :verify_authenticity_token`, `@csrf_exempt`, `csrf: false`). Only shapes with
  a line to cite: a framework that never had a guard is an *absence*, which is the access-control
  lens's job, not a groundable finding.
- **Auth tokens** (`src/authtokens.ts`) — JWT `alg:none`, verified without pinning `algorithms`
  (RS256→HS256 key confusion), decoded without verifying, expiry not enforced (CWE-347/613);
  hardcoded or weak/default secrets (CWE-798/521); OAuth implicit flow, loose `redirect_uri`,
  missing state+PKCE (CWE-757/1385/352); SAML signature disabled (CWE-347); weak password hashing
  (CWE-916).

These are CANDIDATES like taint: an unsafe value in a test or an internal-only service is a
different risk from the same in production. The deeper, absence-based half of these same classes
(does this route actually check ownership? is this the real production config?) stays manual — see
below — and you can confirm what actually ships on the wire with `ultrasec probe`
([probe-playbook.md](probe-playbook.md)).

## What needs YOU (not in the catalog)

Taint enumeration is structural: it connects a known source to a known sink. Everything whose bug
is an **absence** is out of reach and is your job — broken access control and IDOR, missing
authorization, business logic, auth/session/JWT/SSO, crypto misuse beyond weak-hash detection,
deserialization gadget availability, SSRF allow-list bypasses, race conditions and TOCTOU, mass
assignment, ReDoS, file upload, CSRF/CORS, GraphQL field authz, request smuggling, and the
LLM/agentic surface.

One class was **considered and deliberately left out**: **`postMessage` without an origin check
(CWE-346)**. The engine detects `event.data` as a *source*, so flows out of it are enumerated, but
the missing `event.origin` comparison is an **absence** — and absences are the manual pass by
construction. Recording that here rather than dropping it silently is the discipline `coverage`
enforces on the report: a class nobody looked at must be visible as such.

`random` (CWE-330) is the borderline case that was let in. There is no source — the bug is what the
value BECOMES — so it surfaces mainly under `scan --sinks`, and it is rated **low** so it can never
outrank a real flow: a shuffled list and a session token are the same call.

Mechanism-level method per class is in [attack-classes.md](attack-classes.md); the lenses to
apply before you know the class are in [hunting-heuristics.md](hunting-heuristics.md); where each
hides in your stack is [frameworks.md](frameworks.md).

## Extending the catalog

Edit `src/catalog.ts`: add a `SinkRule` (callees + cwe + severity + languages), a
`SourceRule` (a regex tagged by language), or a `SanitizerRule`. Add a fixture
under `tests/fixtures/` and a test asserting the new flow is found (and its
sanitized variant is not). Rebuild (`pnpm build`) and re-run the suite.
