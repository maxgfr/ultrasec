import type { Severity } from "./types.js";
import type { LangSpec, Call } from "./lang.js";
import { expandBraces, globToRe } from "./walk.js";

// The taint catalog: untrusted-input SOURCES, dangerous SINKS, and SANITIZERS
// that neutralize a flow. Pure data + matchers — the deterministic half of the
// "find a candidate, let the AI adjudicate" split. Recall-oriented on purpose:
// a spurious candidate costs the AI a glance; a missed flow is a missed bug.

function appliesTo(languages: string[], langId: string): boolean {
  return languages.includes("*") || languages.includes(langId);
}

export function cweUrl(cwe: string): string {
  const n = cwe.replace(/\D/g, "");
  return `https://cwe.mitre.org/data/definitions/${n}.html`;
}

// ── Sinks ─────────────────────────────────────────────────────────────────
/**
 * What a call has to show, structurally, for a rule not to apply to it.
 *
 * Both shapes read one specific part of the matched call, and both stand on the
 * same proof: the call's receiver chain names a type whose IDENTITY this file can
 * establish. A spelling never establishes it — see `TrustedType`.
 */
export type SinkRefutation =
  /**
   * The verdict is selected by ONE argument, at a position the API fixes
   * (`Cipher.getInstance(transformation, provider)` reads it at 0). Three things
   * have to hold together: the chain names one of `types` and its identity is
   * proven, the argument is a single string literal standing on its own, and its
   * whole value is that type's `safe` set — bare `"AES"` is a fine KEY algorithm
   * and, as a transformation, ECB. `evil.Cipher.getInstance("AES/GCM/NoPadding")`
   * and a file-local `class Cipher` fail the first test and refute nothing.
   */
  | { by: "argument"; index: number; types: readonly TrustedType[] }
  /**
   * The verdict is a claim about where the value CAME FROM, so the proof has to
   * be the call's own receiver/construction chain: the chain, in full, is a
   * construction of a trusted type or a static factory called on one. Everything
   * else keeps the candidate — `(weak ? new Random() : new SecureRandom())`,
   * `factory(SecureRandom)`, `getGenerator("SecureRandom")`, `config.SecureRandom`
   * and `((SecureRandom) rng)` name the API and prove nothing about it.
   */
  | { by: "receiver"; types: readonly TrustedType[] };

/**
 * One type a refutation trusts, spelled the way its API is actually reachable.
 *
 * Everything here exists to answer "is this THAT type?", and a matching name
 * never answers it. A simple name belongs to whoever is in scope, and so does a
 * package root: `java` and `javax` are ordinary identifiers, not keywords, so a
 * variable of that name obscures the package in every EXPRESSION it appears in
 * (JLS 6.4.2/6.5.2) and `java.security.SecureRandom.getInstance(…)` becomes a
 * field walk on somebody's object. `new java.security.SecureRandom()` is the one
 * shape a variable cannot reach: `new` puts the qualified name in TYPE context,
 * where the resolution never considers variables at all.
 *
 * So identity is proven by exactly two shapes, and `identityProven` is where that
 * is decided:
 *
 *  - **Qualified** by the type's own `namespace`, exactly and entirely. In type
 *    context that is proof on its own; in expression context the root has to be
 *    a name the file only ever writes as a qualifier.
 *  - **Unqualified in TYPE context** (`new SecureRandom()`), bound by the one
 *    exact single-type import and not declared as a type by the file itself.
 *
 * An unqualified name in EXPRESSION context (`Cipher.getInstance(…)`,
 * `SecureRandom.getInstance(…)`) is deliberately not on that list. Any local,
 * parameter or field of that name obscures it, and a file this reader can only
 * see one line of at a time cannot rule one out. Those stay candidates.
 */
export interface TrustedType {
  /** Simple name, compared end to end: `SecureRandomWrapper` is not `SecureRandom`. */
  name: string;
  /** The ONE package path the type lives at, head first. A chain qualified with
   *  anything else names a different type that shares the simple name. */
  namespace: readonly string[];
  /** Static factories that return an instance when called ON the type:
   *  `SecureRandom.getInstance(…)`. `getInstance` is a JDK-wide name, so the
   *  owner is what makes it evidence — `KeyStore.getInstance` is not. Read by
   *  `receiver` refutations only. */
  factories?: readonly string[];
  /** The one import specifier that binds the SIMPLE name to this type, for the
   *  `new SecureRandom()` spelling. A package wildcard is deliberately not it: a
   *  type the file declares outranks a wildcard, and the import list alone cannot
   *  see that. Absent ⇒ the unqualified spelling is never provable. */
  simpleImport?: string;
  /** Which literal makes `Type.getInstance(literal, …)` not a finding. Read by
   *  `argument` refutations only, and only once identity is proven. */
  safe?: RegExp;
  /** Languages this spelling exists in. */
  languages: string[];
}

export interface SinkRule {
  kind: string;
  cwe: string;
  severity: Severity;
  languages: string[];
  callees: string[];
  /** If set, a call with a *different* known receiver is skipped (reduces FP). */
  receivers?: string[];
  /** If set, a call with NO receiver (bare `foo(x)`) is skipped — for verb-shaped
   *  callees (`get`/`post`) that are only a sink as a member call (`axios.get`). */
  requireReceiver?: boolean;
  /** If set, the rule only fires in a file importing one of these module
   *  substrings, matched case-INSENSITIVELY (`System.Diagnostics` matches the
   *  `using System.Diagnostics;` an extractor records however it cases it). For
   *  a technology-specific sink whose method name is generic (`client.search` is
   *  LDAP *or* Elasticsearch), the import is what disambiguates. Ignored when
   *  the file has no imports recorded, so the regex extraction tier — which may
   *  not see them — never loses the rule entirely. */
  requireModule?: string[];
  /**
   * The callees are common enough that a bare, uncorroborated call is more
   * likely to be something else entirely (`exec` is `RegExp.prototype.exec` far
   * more often than it is `child_process.exec`). Corroboration is a receiver
   * from `receivers`, or an import matching `requireModule`.
   *
   * Uncorroborated, the hit is NOT simply dropped — that would trade one silent
   * failure for another. It is dropped only when imports were actually
   * extracted and none matched (positive evidence that this is a different
   * `exec`). When the extractor could not see imports at all — the regex tier —
   * the hit survives, DOWNGRADED (`SinkHit.downgraded`), because a critical
   * we cannot substantiate is worse than a medium we can revisit.
   */
  ambiguous?: boolean;
  /**
   * The class has no untrusted SOURCE to trace, so source-gating it hides it.
   *
   * `findSinks` is source-gated: a hit becomes a finding only when the taint BFS
   * connects it back to an untrusted read. For most classes that is the point —
   * an `exec()` fed by a literal is not a command injection. But some classes are
   * dangerous by the shape of the CALL, whatever reaches it, and gating those on
   * a source means they surface only under the opt-in `--sinks` recall pass.
   *
   * CWE-407 shipped that way by accident. It arrived in the same commit as
   * CWE-209 and for the same stated reason — no source exists to find, the cost
   * lives inside the library the caller called — but CWE-209 was written as a
   * line-shape rule (enumerated always) and CWE-407 as a sink rule (enumerated
   * never, without `--sinks`). So the audit finding it was built for, an unbounded
   * `fuzz.extract` on a search query, was invisible to the documented command.
   *
   * A rule may only claim this when its own gates already establish the danger —
   * `requireModule` naming a real string-distance engine, here. It is not a way
   * to skip the source question for a class that still needs it.
   */
  sourceless?: boolean;
  /**
   * Positive evidence, inside the matched call itself, that this call is not what
   * the rule claims — the mirror of `receivers`/`requireModule`, applied to the
   * call's arguments and receiver chain instead of to its callee.
   *
   * A rule whose verdict is selected by a STRING (`Cipher.getInstance("…")`,
   * `x.nextInt()`) is matched on callee and receiver alone, so the literal that
   * decides whether the primitive is weak — the only thing that distinguishes the
   * finding from the recommended API — was never read. The catalog notes said so
   * out loud ("AES/GCM here is not a finding") while the engine emitted exactly
   * that, with a title the matched line refutes.
   *
   * The evidence has to be STRUCTURAL: tied to the thing that makes the call safe
   * — the algorithm in the argument position the API reads it from, the generator
   * the draw was taken from — never to a word that merely appears somewhere in the
   * call's text. A safe transformation named in a provider argument, one branch of
   * a selection resolved at run time, `label("SecureRandom")` handed to a logger:
   * none of those say anything about this call, and all of them stay candidates.
   *
   * Strictly one-directional, and that is the whole safety argument. Anything the
   * reader cannot pin down — a variable, a value assembled at run time, a call it
   * cannot attribute — refutes nothing. Consulted only when the caller passes the
   * file's lines; without them every rule behaves exactly as it did before this
   * field existed.
   */
  refutedBy?: SinkRefutation;
  title: string;
  note: string;
}

/**
 * An AEAD transformation, matched end to end. `Cipher.getInstance` is the only
 * one of these factories that takes a full `algorithm/mode/padding`, and the mode
 * is the whole question: `AES/GCM/NoPadding` authenticates, `AES/ECB/…` and a
 * bare `AES` (which IS ECB on the JVM) do not.
 */
const JVM_AEAD_TRANSFORMATION = /^(?:AES|ARIA|Camellia)(?:_(?:128|192|256))?\/(?:GCM|CCM)(?:\/[A-Za-z0-9]+)?$|^ChaCha20-Poly1305$/i;

/**
 * A strong algorithm NAME, matched end to end. Key and signature factories take a
 * name and no mode, so there is no ECB default to worry about and `AES` alone is
 * exactly right.
 */
const JVM_STRONG_ALGORITHM = /^(?:AES|ChaCha20|RSA|EC|ECDSA|Ed25519|X25519|DiffieHellman|PBKDF2WithHmacSHA(?:224|256|384|512)|HmacSHA(?:224|256|384|512))$/i;

const JVM = ["java", "kotlin", "scala"];

/**
 * The JDK/JCE primitive factories, each at the one package it actually lives at.
 * The `safe` set hangs off the TYPE and not off the receiver's spelling, which is
 * the point: a literal only speaks for a call once the chain has proven whose
 * `getInstance` it is.
 */
const JVM_PRIMITIVE_FACTORIES: readonly TrustedType[] = [
  { name: "Cipher", namespace: ["javax", "crypto"], simpleImport: "javax.crypto.Cipher", safe: JVM_AEAD_TRANSFORMATION, languages: JVM },
  { name: "KeyGenerator", namespace: ["javax", "crypto"], simpleImport: "javax.crypto.KeyGenerator", safe: JVM_STRONG_ALGORITHM, languages: JVM },
  { name: "SecretKeyFactory", namespace: ["javax", "crypto"], simpleImport: "javax.crypto.SecretKeyFactory", safe: JVM_STRONG_ALGORITHM, languages: JVM },
  { name: "KeyPairGenerator", namespace: ["java", "security"], simpleImport: "java.security.KeyPairGenerator", safe: JVM_STRONG_ALGORITHM, languages: JVM },
];

export const SINKS: SinkRule[] = [
  {
    // BEFORE `sql`, which also claims `execute`: `httpClient.execute(request)`
    // is a network call, `stmt.execute(query)` is a query, and only the receiver
    // tells them apart. Receiver-gated hard, so a `stmt`/`ps` receiver falls
    // through to the SQL rule exactly as before; import-gated so a repo with no
    // HTTP client never sees it. `openStream`/`getInputStream` on a `URL` are
    // the JDK's own SSRF shape (OWASP Benchmark's CWE-918 cases).
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["java", "kotlin", "scala"],
    callees: [
      "getForObject",
      "getForEntity",
      "postForObject",
      "postForEntity",
      "exchange",
      "openStream",
      "getInputStream",
      "send",
      "sendAsync",
      "execute",
      "newCall",
      "retrieve",
    ],
    receivers: [
      "restTemplate",
      "RestTemplate",
      "template",
      "client",
      "httpClient",
      "HttpClient",
      "webClient",
      "WebClient",
      "url",
      "URL",
      "u",
      "conn",
      "connection",
      "okHttpClient",
      "http",
    ],
    requireReceiver: true,
    requireModule: ["java.net", "springframework.web", "okhttp", "apache.http", "webflux", "java.net.http"],
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a request URL/host via a JVM HTTP client (RestTemplate, WebClient, HttpClient, OkHttp, `URL.openStream`). Verify the destination is allow-listed (no internal/metadata endpoints).",
  },
  {
    kind: "sql",
    cwe: "CWE-89",
    severity: "high",
    languages: ["javascript", "python", "go", "java", "php", "ruby", "rust", "csharp", "kotlin", "scala"],
    callees: [
      "query",
      "execute",
      "executeQuery",
      "executemany",
      "raw",
      "queryRaw",
      "unsafe",
      "exec_query",
      // JDBC/JPA: the tainted string lands in prepare*, not in the argument-less
      // executeQuery() that follows it. Measured on OWASP Benchmark, omitting
      // these was most of the missed CWE-89.
      "prepareStatement",
      "prepareCall",
      "executeUpdate",
      "executeLargeUpdate",
      "addBatch",
      "nativeSQL",
      "createQuery",
      "createNativeQuery",
      // Spring's JdbcTemplate: every remaining OWASP Benchmark CWE-89 miss (76
      // of 272) was one of these — the SQL string is the first argument.
      // `update` is deliberately absent: too generic a verb to claim.
      "batchUpdate",
      "queryForObject",
      "queryForList",
      "queryForMap",
      "queryForRowSet",
      "queryForInt",
      "queryForLong",
      "queryForStream",
      // PHP's procedural drivers: bare names nothing else uses.
      "mysqli_query",
      "mysqli_real_query",
      "mysqli_multi_query",
      "mysqli_prepare",
      "mysql_query",
      "pg_query",
      "pg_send_query",
      "sqlite_query",
    ],
    title: "SQL injection",
    note: "Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query.",
  },
  {
    // Go's database/sql spells its verbs in CamelCase, so the rule above — all
    // lowercase — never saw `db.Query(...)`, `tx.Exec(...)` or the *Context
    // forms. Receiver-gated hard: `Exec` alone is a Redis pipeline, a Docker
    // client, a template.
    kind: "sql",
    cwe: "CWE-89",
    severity: "high",
    languages: ["go"],
    callees: [
      "Query",
      "QueryRow",
      "QueryContext",
      "QueryRowContext",
      "Exec",
      "ExecContext",
      "Prepare",
      "PrepareContext",
      "Raw",
      "NamedQuery",
      "NamedExec",
      "Select",
      "Get",
    ],
    receivers: ["db", "DB", "tx", "Tx", "conn", "stmt", "pool", "sqlx", "database", "dbx", "gorm"],
    requireReceiver: true,
    title: "SQL injection",
    note: "Tainted data concatenated into a database/sql statement. Verify the query uses `?`/`$1` placeholders with the value passed as an argument, not built with `+` or fmt.Sprintf.",
  },
  {
    // ActiveRecord's string-argument forms. `where("name = '#{q}'")`,
    // `order(params[:sort])` and `pluck(params[:col])` are the Rails injection
    // shapes; the hash/placeholder forms (`where(name: q)`, `where("n = ?", q)`)
    // are the fix and are noted by the sanitizer hint. Receiver-gated so a bare
    // `where(...)` helper does not match; `select` is deliberately absent — in
    // Ruby that is Array#select far more often than a projection.
    kind: "sql",
    cwe: "CWE-89",
    severity: "high",
    languages: ["ruby"],
    callees: ["where", "find_by_sql", "order", "pluck", "joins", "group", "having", "reorder", "count_by_sql", "exists?", "update_all", "delete_all"],
    requireReceiver: true,
    title: "SQL injection",
    note: 'Tainted data interpolated into an ActiveRecord/Sequel query fragment. Use the hash form (`where(name: q)`) or a placeholder (`where("name = ?", q)`); `order`/`pluck` take column names — allow-list them.',
  },
  // -- OS command injection (CWE-78) -----------------------------------------
  // Split into an unambiguous rule plus per-language gated ones, because the two
  // names carrying most of the weight here -- `exec` and `run` -- are among the
  // most reused identifiers in programming. A single `languages: ["*"]` rule
  // with a `receivers` hint could not tell `child_process.exec(cmd)` from
  // `/(LEGIARTI\w+)/.exec(url)`: the extractor reports a receiver only when it
  // is a plain identifier (`readReceiver`), so a regex literal, a call chain and
  // a genuinely bare call all reach `findSinks` looking identical. Measured on a
  // real repo that parses legal-document ids with regexes, that produced 11
  // false CRITICALs out of 17, plus a 12th on an application `run()` defined 68
  // lines above its own call site.
  //
  // So the ambiguous names must be CORROBORATED before firing -- by a known
  // receiver or by a process-module import (`ambiguous: true`, see `findSinks`)
  // -- and a callee the file DEFINES itself never matches the catalog at all
  // (`localDefs`). The unambiguous names below keep firing everywhere, bare
  // included, because nothing else is called `shell_exec` or `execSync`.
  {
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["*"],
    // Names that mean process execution and nothing else, in every language that
    // has them: the `*Sync` forms, PHP's builtins, and `popen`/`Popen`.
    callees: ["execSync", "spawnSync", "shell_exec", "passthru", "proc_open", "popen", "Popen", "check_output", "check_call", "ProcessBuilder", "getRuntime"],
    receivers: ["child_process", "childProcess", "cp", "subprocess", "os", "Runtime", "shell", "shelljs", "getRuntime", "runtime"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    // JS/TS: `exec`/`spawn` are process execution only when they come from a
    // process module. `RegExp.prototype.exec`, redux-saga's `spawn` and any
    // number of `pool.exec`/`db.exec` helpers share the names.
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["javascript"],
    callees: ["exec", "spawn"],
    ambiguous: true,
    receivers: ["child_process", "childProcess", "cp", "shell", "shelljs", "execa", "sh", "zx"],
    requireModule: ["child_process", "execa", "shelljs", "cross-spawn", "node-pty", "zx", "sudo-prompt", "shell-exec"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    // Python: `subprocess.run/call` and `os.system/popen`. Bare `run`/`call` are
    // ordinary application verbs, so the import is what makes them a sink --
    // which is also what catches `from subprocess import run`.
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["python"],
    callees: ["run", "call", "system"],
    ambiguous: true,
    receivers: ["subprocess", "os", "commands", "sp"],
    requireModule: ["subprocess", "os", "pexpect", "invoke", "plumbum"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    // PHP has no receiver for its process builtins and no other meaning for
    // these names -- the same allowed bare-callee exception `error_log` carries
    // in LOG_SINKS. The rest of PHP's family is covered by the unambiguous rule
    // above; this adds bare `exec` and `system`.
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["php"],
    callees: ["exec", "system"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    // Compiled/other languages: `system` is unambiguous there (C, Ruby, Perl),
    // while `exec`/`spawn`/`run` need the Command/Runtime receiver or the
    // process module.
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["ruby", "c_cpp", "lua"],
    callees: ["system"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["ruby", "go", "rust", "java", "kotlin", "scala", "csharp", "c_cpp", "elixir", "swift"],
    callees: ["exec", "spawn", "run", "Command", "output", "Start"],
    ambiguous: true,
    receivers: ["Runtime", "runtime", "exec", "Kernel", "Open3", "Process", "Command", "os", "shell", "System"],
    requireModule: ["os/exec", "std::process", "java.lang.Runtime", "open3", "System.Diagnostics"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
  },
  {
    // BEFORE `code`, which also claims `compile`. `re.compile(userPattern)` is a
    // regex, not arbitrary code: rating it CWE-94 sends the adjudicator to the
    // wrong question and inflates the severity of a real but lesser bug.
    kind: "redos",
    cwe: "CWE-1333",
    severity: "medium",
    languages: ["javascript", "go", "java", "csharp"],
    // Unambiguous constructor names — `new RegExp(p)` / `regexp.MustCompile(p)`
    // carry no receiver, so this rule must not require one.
    callees: ["RegExp", "MustCompile"],
    title: "Regular-expression denial of service (ReDoS)",
    note: "Tainted data compiled as a regex pattern. A crafted pattern (nested quantifiers) burns CPU on any input. Use a fixed pattern, or a linear-time engine (RE2), and bound the input length.",
  },
  {
    kind: "redos",
    cwe: "CWE-1333",
    severity: "medium",
    languages: ["python", "java", "php", "ruby", "javascript"],
    // `compile` is shared with `code` (CWE-94); the receiver is what says this is
    // a regex engine rather than Python's builtin `compile()`.
    callees: ["compile", "Pattern"],
    receivers: ["re", "regexp", "regex", "Pattern", "preg", "regex2"],
    requireReceiver: true,
    title: "Regular-expression denial of service (ReDoS)",
    note: "Tainted data compiled as a regex pattern. A crafted pattern (nested quantifiers) burns CPU on any input. Use a fixed pattern, or a linear-time engine (RE2), and bound the input length.",
  },
  {
    // ReDoS's sibling, and the one nothing here was looking for: the super-linear
    // cost is not in a regex the caller wrote, it is inside a LIBRARY the caller
    // called. Measured on a real audit: `fuzz.extract(userQuery, ~10k variants)`
    // — an O(n·m) Levenshtein DP, synchronous, no early exit — behind a `q`
    // parameter validated with `min(1)` and no `max`. An 8 KB query is ~2·10⁸
    // blocking operations per request, and ten concurrent requests take the
    // process down. The taint walk already had the whole path (query → controller
    // → service → this call); the catalog simply had no sink at the end of it, so
    // nothing was ever emitted.
    //
    // `ambiguous` + `requireModule` is the discipline `exec` gets, for the same
    // reason: `extract`, `ratio`, `distance` and `similarity` are among the most
    // reused method names there are. The import is what says this one is a
    // string-distance engine rather than someone's own helper.
    kind: "algodos",
    cwe: "CWE-407",
    severity: "medium",
    sourceless: true,
    languages: ["javascript", "python", "java", "kotlin", "go"],
    callees: [
      "extract",
      "extractAsPromised",
      "extractAsync",
      "ratio",
      "partial_ratio",
      "token_sort_ratio",
      "token_set_ratio",
      "WRatio",
      "distance",
      "levenshtein",
      "closest",
      "findBestMatch",
      "compareTwoStrings",
      "similarity",
      "get_close_matches",
      "SequenceMatcher",
    ],
    requireModule: [
      "fuzzball",
      "fuzzysort",
      "fast-levenshtein",
      "js-levenshtein",
      "levenshtein",
      "leven",
      "string-similarity",
      "didyoumean",
      "fuse.js",
      "natural",
      "talisman",
      "rapidfuzz",
      "fuzzywuzzy",
      "difflib",
      "commons-text",
      "jellyfish",
      "textdistance",
    ],
    ambiguous: true,
    title: "Algorithmic denial of service (unbounded similarity/distance computation)",
    note: "Tainted data handed to a string-distance / fuzzy-match routine whose cost is super-linear in the input length (Levenshtein DP is O(n·m)) and linear again in the size of the candidate set. Unbounded, a single request can block the event loop for seconds. Bound the input length BEFORE the call (a `max` on the schema, a hard slice) — a MINIMUM length is not a bound.",
  },
  {
    // BEFORE `code`, which also claims `compile` with no receiver gate at all:
    // `xpath.compile(expr)` was reported as CWE-94 code injection, which sends
    // the adjudicator to the wrong remediation (and scored zero on the OWASP
    // Benchmark's CWE-643 cases that compile before they evaluate). Gated on the
    // XPath receivers the rule below already trusts.
    kind: "xpath",
    cwe: "CWE-643",
    severity: "high",
    languages: ["*"],
    callees: ["compile", "evaluate", "selectNodes", "selectSingleNode"],
    receivers: ["xpath", "XPath", "xp", "xPath", "xpathObj", "xpathExpression", "xPathExpression", "expr"],
    requireReceiver: true,
    title: "XPath injection",
    note: "Tainted data compiled into an XPath expression. Use variable binding (XPathVariableResolver / parameterised XPath); escaping quotes by hand is not sufficient.",
  },
  {
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["*"],
    callees: ["eval", "Function", "runInThisContext", "runInContext", "compile", "execfile"],
    title: "Code injection / eval",
    note: "Tainted data evaluated as code. Almost never safe; verify the argument is a constant.",
  },
  {
    // PHP-only: `create_function` compiles its second argument as code (removed
    // in PHP 8 and still shipped in plenty of 7.x). `assert` is a keyword-shaped
    // construct the extractor never records as a call, so its string form is a
    // TEXT_SINKS line rule instead.
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["php"],
    callees: ["create_function", "eval"],
    title: "Code injection / eval",
    note: "Tainted data compiled as PHP code (`create_function` body / `eval`). Almost never safe; replace with a closure or a fixed dispatch table.",
  },
  {
    // Ruby's metaprogramming evaluators. Unambiguous names — nothing else is
    // called `instance_eval` — so no receiver gate is needed.
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["ruby"],
    callees: ["instance_eval", "class_eval", "module_eval", "instance_exec", "class_exec", "module_exec"],
    title: "Code injection / eval",
    note: "Tainted data evaluated as Ruby (`*_eval` with a string argument). Use the block form with a fixed body, or a dispatch table keyed by an allow-listed name.",
  },
  {
    // `obj.send(params[:m])` lets the caller pick the method — any method,
    // private ones included. Receiver-gated: a bare `send(x)` inside a class is
    // ordinary Ruby, and Rails mailers/sockets use the name for other things.
    kind: "reflect",
    cwe: "CWE-470",
    severity: "medium",
    languages: ["ruby"],
    callees: ["send", "public_send", "__send__", "const_get", "method"],
    requireReceiver: true,
    title: "Unsafe reflection",
    note: "Tainted data selecting a method or constant by name. Map the input through an explicit allow-list of permitted targets instead of resolving it dynamically (`public_send` still reaches every public method).",
  },
  {
    // BEFORE the `path` rule, which also claims `open`.
    //
    // `window.open(url)` is navigation, not a filesystem read, but the path rule
    // lists `open` with no `receivers`, and the receiver check in `findSinks` is
    // written `if (rule.receivers && c.receiver && …)` — inert when a rule
    // declares no receivers. So `window.open` matched CWE-22 "Path traversal /
    // archive extraction (zip-slip)" at HIGH, and the `break` on first match
    // stopped any better rule from ever seeing it. Observed on a real repo
    // opening a legifrance.gouv.fr tab with a fixed host and URLSearchParams.
    //
    // Routed to CWE-601 instead: if the host IS attacker-controlled the bug is
    // an open redirect / tabnabbing, which is the question worth asking.
    kind: "redirect",
    cwe: "CWE-601",
    severity: "medium",
    languages: ["javascript"],
    callees: ["open"],
    receivers: ["window", "globalThis", "self", "top", "parent"],
    requireReceiver: true,
    title: "Open redirect / reverse tabnabbing via window.open",
    note: "Tainted data used as a navigation target. Allow-list the destination host (or permit only relative paths), and keep `noopener,noreferrer` on the feature string.",
  },
  {
    // BEFORE `path`, which claims `open` for every receiver: `URI.open(url)`
    // (Ruby's open-uri) is a network fetch, not a file read.
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["ruby"],
    callees: ["open", "open_uri"],
    receivers: ["URI", "OpenURI"],
    requireReceiver: true,
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as an open-uri URL. Verify the destination is allow-listed (no internal/metadata endpoints) — and that a `file://` scheme cannot reach it.",
  },
  {
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["*"],
    callees: [
      "readFile",
      "readFileSync",
      "writeFile",
      "writeFileSync",
      "createReadStream",
      "createWriteStream",
      "sendFile",
      "unlink",
      "open",
      "readdir",
      "appendFile",
      "extractall",
      "extract",
      "unzip",
      "extractAll",
      // Java/C#/Kotlin build a path by CONSTRUCTOR, not by a read* call.
      "File",
      "FileInputStream",
      "FileOutputStream",
      "FileReader",
      "FileWriter",
      "RandomAccessFile",
      "newInputStream",
      "newOutputStream",
      "newBufferedReader",
      // Flask's file responses and PHP's `readfile`: bare names nothing else uses.
      "send_from_directory",
      "send_file",
      "readfile",
    ],
    title: "Path traversal / archive extraction (zip-slip)",
    note: "Tainted data used as a filesystem path, or an archive extracted without validating entry names (zip-slip). Confine to a base dir (basename/realpath + allow-list) and reject entries that escape it.",
  },
  {
    // Go's `os` package spells its verbs in CamelCase — `os.Open`, `os.ReadFile`
    // — so the rule above never matched a single Go file read. Receiver-gated
    // to `os`/`ioutil`: `Open` alone is a database handle, a window, a socket.
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["go"],
    callees: ["Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "ReadDir", "Stat", "Rename", "Mkdir", "MkdirAll"],
    receivers: ["os", "ioutil"],
    requireReceiver: true,
    title: "Path traversal",
    note: "Tainted data used as a filesystem path. Confine to a base dir (filepath.Clean + a prefix check against the base, or os.Root / SecureJoin) and reject `..` segments before the call.",
  },
  {
    // PHP's file builtins. `file_get_contents` and `fopen` accept URLs as well
    // as paths (allow_url_fopen), so the same line is also an SSRF question —
    // the note says so rather than pretending to know which.
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["php"],
    callees: [
      "fopen",
      "file_get_contents",
      "file_put_contents",
      "file",
      "unlink",
      "rename",
      "copy",
      "scandir",
      "opendir",
      "move_uploaded_file",
      "SplFileObject",
    ],
    title: "Path traversal",
    note: "Tainted data used as a PHP filesystem path. `file_get_contents`/`fopen` also accept URLs (allow_url_fopen), so the same call may be an SSRF: allow-list the scheme AND confine the path (basename/realpath against a base dir).",
  },
  {
    // Ruby's File/IO class methods. `File.open` is already caught by the
    // generic rule (`open`, any receiver); `File.read`/`IO.readlines` were not.
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["ruby"],
    callees: ["read", "readlines", "write", "binread", "binwrite", "foreach", "delete", "rename", "readlink", "rm", "rm_rf", "cp", "mv"],
    receivers: ["File", "IO", "Dir", "Pathname", "FileUtils"],
    requireReceiver: true,
    title: "Path traversal",
    note: "Tainted data used as a filesystem path via File/IO/Dir/FileUtils. Confine to a base dir (File.expand_path + start_with? against the base) and reject `..` before the call.",
  },
  {
    // Python's `shutil` copies/moves by path; the source of the copy is as
    // sensitive as the destination.
    kind: "path",
    cwe: "CWE-22",
    severity: "high",
    languages: ["python"],
    callees: ["copy", "copyfile", "copy2", "copytree", "move", "rmtree"],
    receivers: ["shutil", "os"],
    requireReceiver: true,
    title: "Path traversal",
    note: "Tainted data used as a filesystem path in a shutil copy/move/remove. Confine to a base dir (os.path.realpath + a commonpath check against the base) before the call.",
  },
  {
    // CWE-98: PHP file inclusion. The included file is EXECUTED, so a traversal
    // here is code execution (local: log poisoning, `php://filter`; remote:
    // allow_url_include). Its own kind because the remediation is different
    // from a read — an allow-list of includable names, never a path. The
    // parenthesised call form arrives here; the keyword form (`require $x;`)
    // is not a call to the extractor and is matched by a TEXT_SINKS line rule.
    kind: "include",
    cwe: "CWE-98",
    severity: "high",
    languages: ["php"],
    callees: ["include", "require", "include_once", "require_once"],
    title: "File inclusion (LFI/RFI)",
    note: "Tainted data selects a file to include — and an included file is executed. Map the input through an allow-list of known includes (a switch/array lookup), never build the path from it; disable allow_url_include.",
  },
  {
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["*"],
    callees: ["fetch", "request", "urlopen", "urlretrieve", "got", "axios", "openConnection"],
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a request URL/host. Verify the destination is allow-listed (no internal/metadata endpoints).",
  },
  {
    // Member-call form: `axios.get(u)`, `http.get(u)`, `requests.get(u)`,
    // `session.post(u)`, Go `http.Get(u)`. Receiver-gated (requireReceiver) so a
    // bare `get(u)`/`post(u)` — a generic getter/setter — never matches.
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["*"],
    requireReceiver: true,
    callees: ["get", "post", "put", "patch", "head", "delete", "request", "Get", "Post", "Head", "PostForm"],
    receivers: [
      "axios",
      "http",
      "https",
      "got",
      "superagent",
      "fetch",
      "session",
      "client",
      "httpClient",
      "requests",
      "httpx",
      "urllib",
      "urllib2",
      "unirest",
      "Unirest",
    ],
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a request URL/host via an HTTP-client method. Verify the destination is allow-listed (no internal/metadata endpoints). Receiver is generic (an HTTP client vs. a cache/map getter) — confirm it is a network call.",
  },
  {
    // PHP's cURL: the URL goes into `curl_init($url)` or
    // `curl_setopt($ch, CURLOPT_URL, $url)`, never into `curl_exec`. Bare
    // builtins, so no receiver gate — nothing else is called `curl_init`.
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["php"],
    callees: ["curl_init", "curl_setopt", "curl_setopt_array", "curl_exec", "curl_multi_add_handle", "get_headers", "fsockopen"],
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a cURL/socket destination. Verify the host is allow-listed (no internal/metadata endpoints), the scheme is http(s) only, and CURLOPT_FOLLOWLOCATION cannot walk to an internal address.",
  },
  {
    // Ruby's HTTP clients: `Net::HTTP.get(uri)` extracts as receiver `HTTP`,
    // the gem clients under their own names.
    kind: "ssrf",
    cwe: "CWE-918",
    severity: "high",
    languages: ["ruby"],
    callees: ["get", "post", "put", "patch", "delete", "head", "request", "start", "get_response", "post_form", "new", "call"],
    receivers: ["HTTP", "Net", "Faraday", "RestClient", "HTTParty", "Excon", "Typhoeus", "HTTPClient", "http", "client", "conn"],
    requireReceiver: true,
    title: "Server-side request forgery (SSRF)",
    note: "Tainted data used as a request URL/host via a Ruby HTTP client (Net::HTTP, Faraday, RestClient, HTTParty…). Verify the destination is allow-listed (no internal/metadata endpoints) and redirects are not followed blindly.",
  },
  {
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    // `w` is Go's http.ResponseWriter, and Go was missing from this list even
    // though its receiver was: `w.Write([]byte(q))` never matched.
    languages: ["javascript", "python", "php", "ruby", "go"],
    callees: ["send", "write", "end", "html", "render_template_string", "writeHead", "Write"],
    receivers: ["res", "response", "resp", "w"],
    title: "Cross-site scripting (reflected)",
    note: "Tainted data written to an HTML response. Verify it is contextually escaped before reaching the browser.",
  },
  {
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["java", "kotlin", "scala"],
    // `response.getWriter().println(x)` extracts as a BARE `println`, so no
    // receiver gate is possible. The servlet import is what says this file writes
    // HTTP responses at all — without it every System.out.println would match.
    callees: ["println", "print", "write", "append", "printf"],
    // Deliberately NOT receiver-gated. Excluding `out` to spare
    // `System.out.println` was tried and reverted: real Java names its
    // PrintWriter `out` too (`PrintWriter out = response.getWriter()`), and the
    // gate took CWE-79 from 79% to 0% on OWASP Benchmark. Losing the response
    // sink to spare a logging call is the wrong trade — and a servlet writing
    // untrusted input to a log is CWE-117, still worth a look.
    requireModule: ["javax.servlet", "jakarta.servlet", "springframework.web", "javax.ws.rs", "jakarta.ws.rs"],
    title: "Cross-site scripting (reflected)",
    note: "Tainted data written to a servlet response writer. Verify it is contextually escaped (OWASP Encoder / Spring's HtmlUtils) before reaching the browser.",
  },
  {
    // `response.getWriter().format("…%s…", bar)` extracts as a BARE `format`.
    // Kept out of the rule above because `String.format` shares the name: this
    // one lists the writer receivers, so `String.format`/`MessageFormat.format`
    // (a different, known receiver) are skipped while the bare chained form
    // and `out.format` match.
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["java", "kotlin", "scala"],
    callees: ["format"],
    receivers: ["out", "writer", "pw", "printWriter", "w", "response", "resp", "os"],
    requireModule: ["javax.servlet", "jakarta.servlet", "springframework.web", "javax.ws.rs", "jakarta.ws.rs"],
    title: "Cross-site scripting (reflected)",
    note: "Tainted data formatted into a servlet response writer. Verify it is contextually escaped (OWASP Encoder / Spring's HtmlUtils) before reaching the browser.",
  },
  {
    // Go writes its HTML with fmt/io onto the ResponseWriter. `fmt.Fprintf` is
    // just as often a write to os.Stderr — the note says which to check.
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["go"],
    callees: ["Fprintf", "Fprint", "Fprintln", "WriteString", "Copy"],
    receivers: ["fmt", "io"],
    requireReceiver: true,
    title: "Cross-site scripting (reflected)",
    note: "Tainted data written through fmt/io. If the writer is the http.ResponseWriter this is reflected XSS: escape with html.EscapeString or render through html/template. A write to os.Stderr/a file is a different (log/injection) question.",
  },
  {
    // `template.HTML(s)` is the explicit escape hatch out of html/template's
    // contextual escaping — the Go equivalent of dangerouslySetInnerHTML.
    kind: "xss",
    cwe: "CWE-79",
    severity: "high",
    languages: ["go"],
    callees: ["HTML", "JS", "URL", "HTMLAttr", "CSS", "Srcset"],
    receivers: ["template"],
    requireReceiver: true,
    title: "Cross-site scripting (html/template escaping bypass)",
    note: "Tainted data wrapped in template.HTML/JS/URL, which tells html/template NOT to escape it. Render it as a plain string so the template escapes it, or sanitize with a real HTML sanitizer (bluemonday) first.",
  },
  {
    // ASP.NET's raw response writer.
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["csharp"],
    callees: ["Write", "WriteAsync", "BinaryWrite"],
    receivers: ["Response", "response", "writer", "Output", "output"],
    requireReceiver: true,
    title: "Cross-site scripting (reflected)",
    note: "Tainted data written straight to the HTTP response. Encode with HttpUtility.HtmlEncode / the Razor `@` syntax, or return a typed result the framework encodes.",
  },
  {
    kind: "crypto",
    cwe: "CWE-327",
    severity: "medium",
    languages: ["java", "kotlin", "scala", "csharp"],
    // The JVM selects its primitive by STRING, so the callee alone cannot say
    // whether this is MD5 or SHA-256. Receiver-gated to the crypto factories and
    // deliberately recall-oriented: read the algorithm argument in the dossier.
    callees: ["getInstance"],
    // Cipher/key factories → CWE-327 (broken or risky ALGORITHM).
    receivers: ["Cipher", "KeyGenerator", "SecretKeyFactory", "KeyPairGenerator", "Signature"],
    requireReceiver: true,
    // …unless argument 0 — where every one of these factories takes its algorithm
    // — IS spelled out as a literal the note already calls safe. A key factory
    // takes an algorithm NAME, not a transformation, so a bare "AES" there carries
    // no ECB default and is not the same claim as a bare `Cipher.getInstance("AES")`,
    // which stays a finding because on the JVM that IS ECB. `Signature` has no safe
    // set: nothing in its arguments refutes it.
    refutedBy: { by: "argument", index: 0, types: JVM_PRIMITIVE_FACTORIES },
    title: "Weak or attacker-selected cryptographic primitive",
    note: "A JVM crypto primitive chosen by string. Read the algorithm argument: DES/RC4/3DES, or ECB mode, are weak — and an algorithm name built from input is worse. AES/GCM here is not a finding.",
  },
  {
    // Digest factories are their OWN CWE. Reporting a weak hash as CWE-327 sends
    // the reader to the wrong remediation (pick a cipher) instead of the right
    // one (pick a KDF for passwords, SHA-256+ for integrity).
    kind: "crypto",
    cwe: "CWE-328",
    severity: "medium",
    languages: ["java", "kotlin", "scala", "csharp"],
    callees: ["getInstance"],
    receivers: ["MessageDigest", "Mac"],
    requireReceiver: true,
    title: "Weak hash",
    note: "A JVM digest chosen by string. MD5/SHA-1 for a signature, a password or any integrity claim is broken; for a password no plain hash is right at all — use bcrypt/scrypt/Argon2. SHA-256+ for integrity is not a finding.",
  },
  {
    // Go selects its primitive by PACKAGE, so the receiver is the algorithm:
    // `md5.New()`, `sha1.Sum(data)`. `New` is the commonest constructor name in
    // Go (`errors.New`) — the receiver gate is the whole rule.
    kind: "crypto",
    cwe: "CWE-328",
    severity: "medium",
    languages: ["go"],
    callees: ["New", "Sum"],
    receivers: ["md5", "sha1"],
    requireReceiver: true,
    title: "Weak hash",
    note: "MD5/SHA-1 from crypto/md5 or crypto/sha1. For a signature, a password or any integrity claim these are broken; use sha256+ for integrity and bcrypt/scrypt/Argon2 for passwords. A checksum for cache keys is not a finding.",
  },
  {
    kind: "crypto",
    cwe: "CWE-327",
    severity: "medium",
    languages: ["go"],
    callees: ["NewCipher", "NewTripleDESCipher"],
    receivers: ["des", "rc4"],
    requireReceiver: true,
    title: "Weak cryptography",
    note: "DES/3DES/RC4 from crypto/des or crypto/rc4 — broken primitives. Use AES-GCM (crypto/aes + cipher.NewGCM) or chacha20poly1305.",
  },
  {
    // CWE-501: request data written straight into session/context state. The
    // value crosses from untrusted to trusted WITHOUT validation, and everything
    // downstream then reads it as if the application had put it there.
    kind: "trustboundary",
    cwe: "CWE-501",
    severity: "medium",
    languages: ["java", "kotlin", "scala"],
    callees: ["setAttribute", "putValue"],
    title: "Trust boundary violation",
    note: "Untrusted request data stored in session/servlet-context state. Everything downstream reads it as trusted. Validate and normalize BEFORE it crosses, and store a parsed value (an id, an enum) rather than the raw string.",
  },
  {
    kind: "cookie",
    cwe: "CWE-614",
    severity: "medium",
    languages: ["java", "kotlin", "scala"],
    callees: ["addCookie"],
    title: "Cookie set without the protective attributes",
    note: "A cookie carrying request-derived data. Verify Secure (never sent in clear), HttpOnly (unreadable from script) and SameSite are set — and that the value is not sensitive in the first place. The engine cannot see the flags; read them in the dossier.",
  },
  {
    kind: "deserialize",
    cwe: "CWE-502",
    severity: "high",
    languages: ["*"],
    callees: ["loads", "load", "unserialize", "deserialize", "readObject", "load_yaml", "full_load"],
    receivers: ["pickle", "yaml", "marshal", "cPickle", "ObjectInputStream"],
    title: "Insecure deserialization",
    note: "Tainted data deserialized into objects. Use a safe loader (yaml.safe_load, JSON) and never unpickle untrusted input.",
  },
  {
    // .NET's formatters capitalise the verb, and the dangerous ones are known by
    // name: BinaryFormatter, SoapFormatter, LosFormatter, NetDataContractSerializer,
    // JavaScriptSerializer with a resolver, Json.NET with TypeNameHandling.
    kind: "deserialize",
    cwe: "CWE-502",
    severity: "high",
    languages: ["csharp"],
    callees: ["Deserialize", "DeserializeObject", "ReadObject", "UnsafeDeserialize", "Load"],
    receivers: [
      "BinaryFormatter",
      "SoapFormatter",
      "LosFormatter",
      "ObjectStateFormatter",
      "NetDataContractSerializer",
      "JavaScriptSerializer",
      "XmlSerializer",
      "JsonConvert",
      "JsonSerializer",
      "formatter",
      "serializer",
      "bf",
    ],
    requireReceiver: true,
    title: "Insecure deserialization",
    note: "Tainted data deserialized by a .NET formatter. BinaryFormatter/SoapFormatter/LosFormatter/NetDataContractSerializer are unfixable on untrusted input — replace them; for Json.NET verify TypeNameHandling is None, for XmlSerializer that the type is fixed.",
  },
  {
    kind: "crypto",
    cwe: "CWE-327",
    severity: "medium",
    languages: ["*"],
    callees: ["md5", "sha1", "createCipher", "DES", "RC4"],
    title: "Weak cryptography",
    note: "Broken/weak primitive. Use SHA-256+/bcrypt/argon2 and authenticated encryption (AES-GCM).",
  },
  {
    kind: "redirect",
    cwe: "CWE-601",
    severity: "medium",
    languages: ["javascript", "python", "php", "ruby"],
    callees: ["redirect"],
    receivers: ["res", "response", "resp"],
    title: "Open redirect",
    note: "Tainted data used as a redirect target. Allow-list the destination or only permit relative paths.",
  },
  {
    // The JVM, Go and .NET spellings. `response.sendRedirect(url)` (OWASP
    // Benchmark's CWE-601 shape), `http.Redirect(w, r, url, code)`, ASP.NET's
    // `Response.Redirect(url)` and the bare controller helper `return
    // Redirect(returnUrl)` — the single most common .NET open redirect. Not
    // receiver-gated, because that last form has no receiver; a DIFFERENT
    // known receiver still skips (`router.Redirect`).
    kind: "redirect",
    cwe: "CWE-601",
    severity: "medium",
    languages: ["java", "kotlin", "scala", "go", "csharp"],
    callees: ["sendRedirect", "Redirect", "RedirectPermanent", "RedirectToAction", "RedirectToRoute", "RedirectToPage"],
    receivers: ["response", "resp", "res", "http", "Response", "ctx", "c", "w", "this"],
    title: "Open redirect",
    note: "Tainted data used as a redirect target. Allow-list the destination host, or accept only a relative path (reject `//`, `\\`, and a scheme) — `LocalRedirect`/`Url.IsLocalUrl` in ASP.NET.",
  },
  {
    kind: "nosql",
    cwe: "CWE-943",
    severity: "high",
    languages: ["javascript", "python"],
    callees: ["find", "findOne", "findOneAndUpdate", "findOneAndDelete", "updateOne", "deleteOne", "aggregate", "mapReduce", "distinct"],
    receivers: ["db", "collection", "coll", "Model", "model", "User", "users", "mongo", "mongoose", "repo", "repository"],
    title: "NoSQL injection",
    note: "Tainted data shaped into a NoSQL query object/operator ($where, $ne, $gt …). Coerce types and reject operator keys (mongo-sanitize); never pass a raw request object as a filter.",
  },
  {
    kind: "ssti",
    cwe: "CWE-1336",
    severity: "high",
    languages: ["*"],
    callees: ["from_string", "renderString", "compileString", "Template", "createTemplate", "renderTemplate"],
    title: "Server-side template injection (SSTI)",
    note: "Tainted data compiled into a template. Render data as context VALUES, never concatenate into the template source; enable autoescaping.",
  },
  {
    kind: "xxe",
    cwe: "CWE-611",
    severity: "high",
    languages: ["*"],
    callees: [
      "parseString",
      "parseXml",
      "parseFromString",
      "fromstring",
      "SAXParser",
      "DocumentBuilder",
      "XMLReader",
      "createDocument",
      // PHP: libxml entity loading is a global switch; these all honour it.
      "simplexml_load_string",
      "simplexml_load_file",
      "loadXML",
      "loadHTML",
      "xml_parse",
    ],
    title: "XML external entity (XXE)",
    note: "Tainted XML parsed with external entities/DTDs enabled. Disable entity resolution (resolve_entities=False / FEATURE_SECURE_PROCESSING / noent off).",
  },
  {
    kind: "ldap",
    cwe: "CWE-90",
    severity: "high",
    languages: ["*"],
    callees: ["search", "bind", "searchSync"],
    receivers: ["ldap", "ldapClient", "ldapjs", "client", "conn", "connection", "ld", "idc", "ctx", "dirContext", "dctx", "ic"],
    // `search` is the most over-loaded method name in the catalog: without these
    // two gates the rule fired on every Elasticsearch `client.search()` and on
    // every bare `search(opts)` helper — 30+ high-severity false positives on a
    // single real repo, drowning the findings that mattered. The receiver list
    // stays permissive (an ldapjs client IS usually named `client`); the import
    // is what says which technology this actually is.
    requireReceiver: true,
    requireModule: ["ldap", "activedirectory", "unboundid", "novell.ldap", "javax.naming", "jakarta.naming"],
    title: "LDAP injection",
    note: "Tainted data concatenated into an LDAP filter/DN. Escape with the LDAP escaping API (ldap.escape / escapeFilter / escapeDN).",
  },
  {
    // The JVM writes LDAP fully qualified (`javax.naming.directory.InitialDirContext`)
    // and imports nothing, so the import gate above can never fire. Gated on the
    // context receivers instead, which are not names anything else uses.
    kind: "ldap",
    cwe: "CWE-90",
    severity: "high",
    languages: ["java", "kotlin", "scala"],
    callees: ["search", "bind"],
    // `ctx`/`ic`/`context` are what the JDK's own examples and the OWASP
    // Benchmark name their InitialDirContext; `ldapCtx`/`ldap` are the other
    // spellings seen in the wild.
    receivers: ["idc", "dirContext", "dctx", "ldapContext", "initialDirContext", "dirCtx", "ctx", "ic", "context", "ldapCtx", "ldap", "ldapTemplate"],
    requireReceiver: true,
    title: "LDAP injection",
    note: "Tainted data concatenated into an LDAP filter or DN. Escape with the LDAP escaping API (ESAPI encodeForLDAP / encodeForDN); quoting by hand does not cover the filter metacharacters.",
  },
  {
    // No source is required for this class — the bug is what the value BECOMES,
    // not what flows in — so it mostly surfaces under `scan --sinks` (orphan
    // sinks). Kept low so it never outranks a flow: a shuffled list and a
    // session token are the same call.
    kind: "random",
    cwe: "CWE-330",
    severity: "low",
    languages: ["*"],
    callees: ["Random", "nextInt", "nextFloat", "nextDouble", "nextLong", "mt_rand", "randint", "randrange", "shuffle"],
    // The title is a claim about WHICH generator this draw came from, so only the
    // construction the draw hangs off can settle it — and only when that
    // construction is the JDK's and not something else wearing its name.
    // `new java.security.SecureRandom().nextInt()` says so, and so does the
    // unqualified `new SecureRandom()` in a file that imports exactly that class
    // and declares no type of its own by that name. `evil.SecureRandom()`,
    // `fake.SecureRandom.getInstance()`, a local `static Random SecureRandom()`,
    // a file-local `class SecureRandom extends Random`, a file that binds `java`
    // as a variable — each matches the name and none is the CSPRNG, so each stays
    // a candidate. A CSPRNG named anywhere else in the chain (a ternary branch, a
    // factory argument, a string, a field) says nothing either.
    //
    // Java only. Python's `secrets`/`random.SystemRandom` read the same on the
    // page and are not decidable from it: a parameter, a lambda parameter, a
    // tuple unpack, a `with … as`, a walrus or a `global` in another function all
    // rebind the module, and enumerating those forms line by line is guesswork
    // with a missed bug on the wrong side of it. Nothing Python refutes.
    refutedBy: {
      by: "receiver",
      types: [
        {
          name: "SecureRandom",
          namespace: ["java", "security"],
          factories: ["getInstance", "getInstanceStrong"],
          simpleImport: "java.security.SecureRandom",
          languages: JVM,
        },
      ],
    },
    title: "Predictable value from a non-cryptographic RNG",
    note: "Only a finding when the value becomes a token, key, session id, password-reset link or nonce — for a shuffle or a jitter it is nothing. Read what it is used for, then require a CSPRNG (SecureRandom / crypto.randomBytes / secrets).",
  },
  {
    kind: "random",
    cwe: "CWE-330",
    severity: "low",
    languages: ["*"],
    // `Math.random()` / `random.random()`. Receiver-gated so a project's own
    // `random(list)` helper is not swept in.
    callees: ["random"],
    receivers: ["Math", "random", "rng", "np"],
    requireReceiver: true,
    title: "Predictable value from a non-cryptographic RNG",
    note: "Only a finding when the value becomes a token, key, session id, password-reset link or nonce — for a shuffle or a jitter it is nothing. Read what it is used for, then require a CSPRNG (crypto.randomBytes / secrets / SecureRandom).",
  },
  {
    kind: "crlf",
    cwe: "CWE-93",
    severity: "medium",
    languages: ["javascript", "python", "java", "go", "php", "ruby"],
    callees: ["setHeader", "header", "addHeader", "setRequestHeader", "putHeader"],
    receivers: ["res", "response", "resp", "w", "headers"],
    title: "HTTP response splitting / header (CRLF) injection",
    note: "Tainted data written into a response header. Strip CR/LF (\\r\\n) or use an API that rejects them.",
  },
  {
    kind: "proto",
    cwe: "CWE-1321",
    severity: "high",
    languages: ["javascript"],
    callees: ["merge", "mergeWith", "extend", "defaultsDeep", "setWith", "set"],
    receivers: ["_", "lodash", "$", "jQuery", "angular", "Object", "util"],
    title: "Prototype pollution",
    note: "Tainted keys deep-merged into an object can reach Object.prototype (__proto__/constructor/prototype). Reject those keys or use a null-prototype target / Map.",
  },
  {
    kind: "buffer",
    cwe: "CWE-120",
    severity: "high",
    languages: ["c_cpp"],
    callees: ["strcpy", "strcat", "sprintf", "gets", "memcpy", "stpcpy", "vsprintf"],
    title: "Classic buffer overflow (unbounded copy)",
    note: "Best-effort (C/C++): tainted data into an unbounded copy. Prefer the bounded forms (strncpy/snprintf/memcpy with a checked length). Pair with cppcheck/gosec.",
  },
  {
    // The blind spot the `command` sanitizer hint creates. Moving off a shell
    // string onto an argv array kills metacharacter injection and NOTHING else:
    // if the attacker controls an ARGUMENT, plenty of ordinary binaries will
    // execute code for them anyway — `git --upload-pack=`, `curl -o`,
    // `ssh -oProxyCommand=`, `tar --checkpoint-action=`, `find -exec`,
    // `rsync -e`. So the argv forms are their own sink, not a safe harbour.
    kind: "argv",
    cwe: "CWE-88",
    severity: "high",
    languages: ["*"],
    callees: ["execFile", "execFileSync", "execv", "execve", "execvp", "posix_spawn", "CreateProcess"],
    title: "Argument injection",
    note: "Tainted data used as an ARGUMENT to a program. An argv array stops shell metacharacters, not option injection: verify the value cannot start with '-' and is not a path/URL the callee will act on.",
  },
  {
    kind: "reflect",
    cwe: "CWE-470",
    severity: "medium",
    languages: ["*"],
    callees: ["getattr", "setattr", "forName", "import_module", "__import__", "newInstance", "getMethod", "getDeclaredMethod", "CreateInstance"],
    title: "Unsafe reflection",
    note: "Tainted data selecting a class, module, method or attribute by name. Map the input through an explicit allow-list of permitted targets instead of resolving it dynamically.",
  },
  {
    kind: "xpath",
    cwe: "CWE-643",
    severity: "high",
    languages: ["*"],
    callees: ["selectNodes", "selectSingleNode", "xpath", "xpath_eval", "compile_xpath", "XPathSelect", "evaluate"],
    receivers: ["xpath", "XPath", "xp", "xPath", "xpathObj", "doc", "document", "tree", "root", "xml", "node"],
    requireReceiver: true,
    title: "XPath injection",
    note: "Tainted data concatenated into an XPath expression. Use variable binding (XPathVariableResolver / parameterised XPath); escaping quotes by hand is not sufficient.",
  },
  {
    // AFTER xpath, which also claims `evaluate`: `Velocity.evaluate(ctx, out,
    // tag, userString)` and FreeMarker's `new Template(...).process` compile
    // the untrusted string as a template. Receiver- and import-gated: the
    // engine's own name is what says this `evaluate`/`process` is a template.
    kind: "ssti",
    cwe: "CWE-1336",
    severity: "high",
    languages: ["java", "kotlin", "scala"],
    callees: ["evaluate", "process", "merge", "mergeTemplate", "parse"],
    receivers: ["Velocity", "velocity", "velocityEngine", "engine", "template", "Template", "cfg", "configuration", "freemarker", "templateEngine", "ve"],
    requireReceiver: true,
    requireModule: ["velocity", "freemarker", "thymeleaf", "pebble", "jinjava", "mustache", "handlebars"],
    title: "Server-side template injection (SSTI)",
    note: "Tainted data compiled/evaluated as a JVM template (Velocity/FreeMarker/Thymeleaf). Render data as context VALUES on a fixed template, never build the template source from input; on Thymeleaf avoid `__${...}__` preprocessing with user data.",
  },
  {
    kind: "massassign",
    cwe: "CWE-915",
    severity: "medium",
    languages: ["javascript", "python", "ruby", "php", "java"],
    // ORM binders only. `Object.assign` is deliberately NOT here: the class turns
    // on WHICH object receives the fields, and `Object.assign(user, req.body)`
    // (mass assignment) is indistinguishable from `Object.assign({}, req.body)`
    // (a safe copy) without reading the arguments. Flagging both put a false
    // positive on the prototype-pollution safe twin. That shape stays a job for
    // the manual pass — see references/attack-classes.md.
    callees: ["setAttributes", "bulkCreate", "fill", "update_attributes", "populate", "assign_attributes"],
    title: "Mass assignment / unsafe object binding",
    note: "A whole request object bound onto a model. Whitelist the assignable fields explicitly — otherwise an attacker sets `isAdmin`, `role`, `balance` or the primary key.",
  },
  {
    kind: "csv",
    cwe: "CWE-1236",
    severity: "medium",
    languages: ["*"],
    callees: ["writerow", "writerows", "to_csv", "fputcsv", "writeRecords", "csvStringify"],
    title: "CSV formula injection",
    note: "Tainted data written into a spreadsheet cell. A value starting with = + - @ TAB or CR executes when opened in Excel/Sheets. Prefix such values with an apostrophe or reject them.",
  },
  {
    // The 2026 surface, and the one no scanner models: a model's output is
    // ATTACKER-INFLUENCED whenever anything it read was. See LLM_SOURCES for the
    // other direction (model output flowing into a classic sink), which is the
    // more severe of the two.
    kind: "llm",
    cwe: "CWE-1427",
    severity: "high",
    languages: ["*"],
    callees: ["create", "invoke", "run", "predict", "complete", "generate", "generate_content", "chat", "send_message", "stream"],
    receivers: ["completions", "messages", "chat", "llm", "model", "client", "openai", "anthropic", "agent", "chain", "genai"],
    requireReceiver: true,
    requireModule: ["openai", "anthropic", "langchain", "llamaindex", "generativeai", "genai", "bedrock", "ollama", "mistralai", "cohere", "@ai-sdk"],
    title: "Prompt injection (untrusted input reaches a model prompt)",
    note: "Tainted data concatenated into a prompt. The model cannot separate instructions from data: assume the attacker controls the output, and gate what that output is ALLOWED to do (tools, sinks) rather than trying to sanitize the prompt.",
  },
];

/**
 * Sink kinds whose danger is the shape of the call, not the provenance of its
 * argument — enumerated even without the opt-in `--sinks` recall pass.
 *
 * Derived from the rules rather than hand-listed, so a rule that claims
 * `sourceless` cannot silently fail to be enumerated.
 */
export const SOURCELESS_SINK_KINDS: ReadonlySet<string> = new Set(SINKS.filter((r) => r.sourceless).map((r) => r.kind));

/**
 * Sinks that are ASSIGNMENTS, not calls, and so are invisible to a call-based
 * catalog. `el.innerHTML = userInput` is the single most common DOM XSS shape in
 * the wild and matching `calls` can never see it. Matched by regex per line, the
 * same way SOURCES are.
 */
export interface TextSinkRule {
  kind: string;
  cwe: string;
  severity: Severity;
  languages: string[];
  re: RegExp;
  /**
   * Require the ASSIGNED VALUE to be something other than a constant.
   *
   * These rules match a line, and reachability is closed by "a source at or
   * above the sink line in the same file" — so `script.src = "https://…"`, a
   * bare string literal, was reported as DOM XSS because an unrelated
   * `location.hash` read appeared earlier in the file. A constant cannot carry
   * tainted data, whatever else the function does.
   *
   * Set ONLY on the dot-assignment rules. It must never go on the framework rule
   * (`v-html="expr"`, `[innerHTML]="expr"`), where the quotes delimit an HTML
   * attribute and its CONTENTS are the expression — treating that as a literal
   * would silently drop real template XSS.
   */
  requiresDynamicValue?: boolean;
  /** What to show as the "callee" in the finding title. */
  label: string;
  title: string;
  note: string;
}

export const TEXT_SINKS: TextSinkRule[] = [
  {
    kind: "domxss",
    cwe: "CWE-79",
    severity: "high",
    languages: ["javascript"],
    re: /\.\s*(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)/,
    requiresDynamicValue: true,
    label: "innerHTML",
    title: "DOM XSS (HTML sink)",
    note: "Tainted data assigned to innerHTML/outerHTML executes any markup it contains. Assign via textContent, or sanitize with DOMPurify and a Trusted Types policy.",
  },
  {
    kind: "domxss",
    cwe: "CWE-79",
    severity: "high",
    languages: ["javascript"],
    re: /dangerouslySetInnerHTML\s*=|\bv-html\s*=|\[innerHTML\]\s*=/,
    label: "framework HTML bypass",
    title: "DOM XSS (framework escaping bypass)",
    note: "React `dangerouslySetInnerHTML`, Vue `v-html` and Angular `[innerHTML]` deliberately disable the framework's escaping. Sanitize the value first, or render it as text.",
  },
  {
    kind: "domxss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["javascript"],
    re: /\.\s*(?:src|href|action|formaction|srcdoc)\s*=(?!=)/,
    requiresDynamicValue: true,
    label: "URL attribute",
    title: "DOM XSS via a URL attribute",
    note: "Tainted data assigned to src/href executes when the scheme is `javascript:` or `data:`. Allow-list the scheme before assigning.",
  },
  {
    // `eval` handed to a higher-order function instead of being called.
    //
    // `df['action_eventname'].apply(eval)` evaluates every row of a column as
    // Python. The catalog matches CALLS, and this is not one — `eval` appears
    // only as an argument, so the extractor records `apply` and the code-injection
    // rule never fires. Bandit's B307 misses it for the same reason: its blacklist
    // is keyed on call nodes.
    //
    // It is the exact shape a real audit found by hand, over a column of analytics
    // event names that any visitor to the public site can set. Kept narrow — the
    // pandas/builtin apply-family plus a name that can only mean the interpreter.
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["python"],
    re: /\.\s*(?:apply|applymap|map|transform|agg|aggregate|pipe)\s*\(\s*(?:eval|exec)\s*[,)]|\b(?:map|filter)\s*\(\s*(?:eval|exec)\s*,/,
    label: "eval as a callable",
    title: "Code injection (the interpreter applied to data)",
    note: "`eval`/`exec` passed as the function argument of an apply/map, so every value in the series is executed as Python. Nothing about the call site says which values those are — find where the column comes from before deciding this is safe. Parse with `ast.literal_eval` or `json.loads` instead.",
  },
  {
    // PHP's keyword form of inclusion — `require $page;`, `include_once $f;` —
    // is not a call to the extractor (no parentheses), so the `include` sink
    // rule never sees it. A literal argument stays out: `require_once
    // __DIR__ . '/x.php'` is every PHP file's first line and cannot carry
    // input. Only a variable directly after the keyword matches.
    kind: "include",
    cwe: "CWE-98",
    severity: "high",
    languages: ["php"],
    re: /^\s*(?:include|require)(?:_once)?\s+\$\w+/,
    label: "include/require (keyword form)",
    title: "File inclusion (LFI/RFI)",
    note: "A variable selects the file to include, and an included file is executed. Map the input through an allow-list of known includes, never build the path from it; disable allow_url_include.",
  },
  {
    // `assert($userString)` evaluates the string as PHP (before 8.0, and with
    // zend.assertions on). Keyword-shaped to the extractor, so a line rule.
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["php"],
    re: /\bassert\s*\(\s*\$\w+/,
    label: "assert (string form)",
    title: "Code injection / eval",
    note: "A variable passed to `assert` is evaluated as PHP code on PHP < 8 (and wherever zend.assertions is on). Assert an expression, never a string built from input.",
  },
  // ── The caught error, handed straight to the caller (CWE-209) ─────────────
  //
  // A line sink rather than a flow, because the line carries BOTH halves: the
  // error value and the write that returns it. There is no untrusted SOURCE to
  // trace here — the tainted value is the exception itself, produced by the
  // server — so no source→sink walk could ever have reached this class, and
  // nothing else in the engine asks the question.
  //
  // The gap between the writer and the error expression forbids `)`, which is
  // what keeps `const d = await res.json(); log(err.message)` — two unrelated
  // statements on one line — from matching. An explicit `.status(NNN)` hop is
  // allowed through because `res.status(500).json({ error: err.message })` is
  // the single most common shape of this bug.
  {
    kind: "errleak",
    cwe: "CWE-209",
    severity: "low",
    languages: ["javascript"],
    re: /(?:\bNextResponse|\bJsonResponse|\b(?:res|resp|response|reply|ctx)\w*)\s*(?:\.\s*status\s*\(\s*\d{3}\s*\))?\s*\.\s*(?:json|send|end|write|text)\s*\([^\n)]{0,160}?(?:\bString\s*\(\s*(?:err|error|e|ex|exc)\b|\b(?:err|error|e|ex|exc|exception)\s*\.\s*(?:message|stack|stackTrace|detail|details|sqlMessage|toString)\b|\$\{\s*(?:err|error|e)\s*\})/,
    label: "error → response body",
    title: "Error detail returned to the client (CWE-209)",
    note: "The caught error's own text is written into the HTTP response. Upstream errors leak internals the caller should never see — driver and index names, SQL fragments, file paths, the status text of a third-party API. Return a fixed message and keep the detail in the log / the exception tracker.",
  },
  {
    // Flask/Django's shape of the same bug. Bare-callee rather than
    // receiver-dotted, so it needs its own rule.
    kind: "errleak",
    cwe: "CWE-209",
    severity: "low",
    languages: ["python"],
    re: /\b(?:jsonify|JsonResponse|HttpResponse|HttpResponseServerError|make_response|abort)\s*\([^\n)]{0,160}?(?:\bstr\s*\(\s*(?:e|err|error|exc|ex)\s*\)|\brepr\s*\(\s*(?:e|err|error|exc|ex)\s*\)|\btraceback\s*\.\s*format_exc|\b(?:e|err|error|exc|ex)\s*\.\s*(?:message|args)\b)/,
    label: "error → response body",
    title: "Error detail returned to the client (CWE-209)",
    note: "The caught exception's own text is written into the HTTP response. Upstream errors leak internals the caller should never see — driver names, SQL fragments, file paths, a full traceback. Return a fixed message and keep the detail in the log / the exception tracker.",
  },
];

/** A string or template literal with nothing interpolated into it. */
const PURE_QUOTED = /^(['"])(?:\\.|(?!\1)[^\\])*\1$/;

/**
 * Is the value assigned on this line a compile-time constant?
 *
 * `rhs` is everything after the matched `=`. Anything this cannot positively
 * prove constant is treated as dynamic — a value continued on the next line, a
 * concatenation, an identifier, an interpolated template. Recall is the default;
 * only a literal it can see in full is dropped.
 */
export function isConstantAssignment(rhs: string): boolean {
  const v = rhs
    .trim()
    .replace(/[;,]\s*$/, "")
    .trim();
  if (!v) return false; // value is on the next line — cannot tell, so keep it
  if (v.startsWith("`") && v.endsWith("`") && v.length >= 2) return !v.includes("${");
  return PURE_QUOTED.test(v);
}

export function findTextSinks(lang: LangSpec, content: string): SinkHit[] {
  const out: SinkHit[] = [];
  const lines = content.split(/\r?\n/);
  const rules = byLanguage(textSinkByLang, TEXT_SINKS, lang.id);
  if (!rules.length) return out;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of rules) {
      const m = rule.re.exec(line);
      if (!m) continue;
      // The match ends just past the `=`, so the remainder of the line is the
      // assigned value.
      const rhs = rule.requiresDynamicValue
        ? line
            .slice(m.index + m[0].length)
            .trim()
            .replace(/[;,]\s*$/, "")
            .trim()
        : undefined;
      if (rule.requiresDynamicValue && isConstantAssignment(line.slice(m.index + m[0].length))) continue;
      out.push({
        line: i + 1,
        callee: rule.label,
        kind: rule.kind,
        cwe: rule.cwe,
        severity: rule.severity,
        title: rule.title,
        note: rule.note,
        ...(rhs ? { assigned: rhs } : {}),
      });
      break; // first matching rule wins, as with call sinks
    }
  }
  return out;
}

// Logging-hygiene sinks (CWE-117 — log injection): calls that write to a log.
// Deliberately kept OUT of `SINKS` — logging-hygiene findings are strictly
// opt-in (`scan --log-hygiene`), so the default sink-matching enumeration is
// untouched unless a caller explicitly unions this in (`findSinks`'s optional
// `extraSinks` param). Every rule is receiver-gated HARD (`requireReceiver:
// true`) so a bare `log(x)`/`info(x)` — no known logger receiver — never
// matches, EXCEPT the PHP bare `error_log`: PHP has no receiver for it at all,
// so gating on one would make the rule unreachable.
export const LOG_SINKS: SinkRule[] = [
  {
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["javascript"],
    requireReceiver: true,
    receivers: ["console", "logger", "log", "winston", "pino", "bunyan"],
    callees: ["log", "info", "warn", "error", "debug", "trace"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["python"],
    requireReceiver: true,
    receivers: ["logging", "logger", "log"],
    callees: ["info", "warning", "error", "debug", "exception", "critical"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["go"],
    requireReceiver: true,
    receivers: ["log", "logger", "zap", "sugar"],
    callees: ["Print", "Printf", "Println", "Info", "Infof", "Error", "Errorf", "Warn", "Warnf"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["ruby"],
    requireReceiver: true,
    receivers: ["logger"],
    callees: ["info", "warn", "error", "debug"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    // PHP has no receiver for error_log — an allowed bare-callee exception, since
    // gating it on a receiver would make the rule unreachable.
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["php"],
    callees: ["error_log"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["php"],
    requireReceiver: true,
    receivers: ["logger", "monolog"],
    callees: ["info", "warning", "error", "debug"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization; typically low severity.",
  },
  {
    // JVM: SLF4J/Log4j/JUL under the names people actually give the field.
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["java", "kotlin", "scala"],
    requireReceiver: true,
    receivers: ["logger", "log", "LOGGER", "LOG", "logging", "slf4jLogger", "_logger"],
    callees: ["info", "warn", "error", "debug", "trace", "fatal", "severe", "warning", "fine", "finer", "finest", "config"],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization (Log4j 2's `%enc{%m}{CRLF}`, or strip \\r\\n before the call); typically low severity.",
  },
  {
    // .NET: Microsoft.Extensions.Logging's `Log*` family, plus Console.
    kind: "log",
    cwe: "CWE-117",
    severity: "low",
    languages: ["csharp"],
    requireReceiver: true,
    receivers: ["_logger", "logger", "Logger", "Log", "log", "_log", "Console", "Trace", "Debug"],
    callees: [
      "LogInformation",
      "LogWarning",
      "LogError",
      "LogDebug",
      "LogCritical",
      "LogTrace",
      "Log",
      "WriteLine",
      "Write",
      "Info",
      "Warn",
      "Error",
      "Debug",
      "Fatal",
    ],
    title: "Log injection (unsanitized log write)",
    note: "Untrusted data written to a log without newline/CRLF stripping — verify neutralization (strip \\r\\n, or a structured logger with the value as a property, not in the template); typically low severity.",
  },
  // Rust is deliberately absent: `info!(...)`/`tracing::warn!(...)` are macros,
  // which the extractor does not record as calls, so a rule here could never
  // fire. Log-shaped macros need a line rule, not a call rule.
];

export interface SinkHit {
  line: number;
  callee: string;
  receiver?: string;
  kind: string;
  cwe: string;
  severity: Severity;
  title: string;
  note: string;
  /**
   * For an ASSIGNMENT sink (`el.innerHTML = …`, `script.src = …`), the text of
   * the assigned value.
   *
   * This is the evidence #13 asked for — "require a real flow edge into the
   * sink's attribute". The engine does NOT decide it: reachability here is
   * closed by "a source at or above the sink line in the same file", which is
   * co-location, and tightening that mechanically would trade recall on DOM XSS,
   * the class where real bugs actually live. So the value is surfaced instead,
   * next to the names the def-use walk was tracking, and the adjudicator can see
   * in one line whether anything tainted arrives.
   */
  assigned?: string;
  /** Why this hit was reported below its catalog severity — set when an
   *  `ambiguous` rule matched a bare call the extractor could not corroborate.
   *  Absent on every ordinary hit, so consumers that ignore it behave exactly as
   *  before this field existed. */
  downgraded?: string;
}

// ── The call a refutation has to belong to ──────────────────────────────
//
// `refutedBy` reads two specific parts of the matched call — an argument at a
// fixed position, or the chain the call hangs off — and three things sit between
// those and the source text.
//
// A call is not reliably one line: every Java formatter wraps a long one, so
// `Cipher.getInstance(\n  "AES/GCM/NoPadding", provider)` puts the literal on the
// line BELOW the callee. A line is not reliably one call:
// `Cipher.getInstance("DES"); Cipher.getInstance("AES/GCM/NoPadding");` is two,
// and reading the whole line would let the safe one clear the weak one — the
// exact inversion of what the rule is for. And a call is not its text: a strong
// transformation named in a PROVIDER argument, one branch of `pick("DES",
// "AES/GCM/NoPadding")`, `label("SecureRandom")` handed to a logger — all three
// contain the safe words and none of them is safe.
//
// So the text is cut three times. The WINDOW is the statement: the line, extended
// forward only while the parentheses it opened are still unbalanced, which is
// exactly the call's own arguments and cannot reach the next statement. Inside
// that window one OCCURRENCE is picked out — its receiver chain, its callee, its
// own balanced argument list. And from that occurrence only two things are ever
// handed to a rule, both of them PARSED and neither of them text: its chain as a
// sequence of dotted names (`ChainShape`), and its top-level arguments reduced to
// the value of each one that is a single string literal standing alone. A nested
// call, a concatenation and a variable all reduce to "unreadable", so nothing
// inside them can speak for the call that contains them; a ternary, a cast and an
// index make the chain opaque, for the same reason and with the same effect.
//
// A `Call` carries no column, so WHICH occurrence of the callee on the line the
// record means is not always knowable. When it is not — two occurrences the
// receiver cannot separate, a callee whose text is not on its own line — there is
// no attribution and no refutation: the candidate stays. That asymmetry is
// deliberate. A kept candidate costs one adjudication; a dropped one is a missed
// bug, and this gate exists only to remove findings, so every uncertainty inside
// it has to fall the other way.

/** Languages where `#` starts a comment. PHP has both `#` and `//`; its `#[Attr]`
 *  is an attribute, not a comment. */
const HASH_COMMENT_LANGS: ReadonlySet<string> = new Set(["python", "ruby", "php", "shell", "elixir"]);

/**
 * Drop comments, keep string literals, and report the net parenthesis depth the
 * line leaves open. Both halves matter: the evidence `refutedBy` looks for lives
 * INSIDE a literal, and a `// TODO: move to AES/GCM` must not be able to refute
 * the finding it is asking someone to fix.
 */
function scanStatementLine(text: string, hash: boolean): { clean: string; net: number } {
  let clean = "";
  let net = 0;
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      clean += ch;
      if (ch === "\\") {
        i++;
        if (i < text.length) clean += text[i];
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      clean += ch;
      continue;
    }
    // `//` is a comment everywhere it is not floor division; in Python cutting at
    // `a // b` only shortens the window, which can lose a refutation and never
    // invent one — the safe direction.
    if (ch === "/" && text[i + 1] === "/") break;
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end < 0) break;
      i = end + 1;
      continue;
    }
    if (hash && ch === "#" && text[i + 1] !== "[") break;
    if (ch === "(") net++;
    else if (ch === ")") net--;
    clean += ch;
  }
  return { clean, net };
}

/** How far a wrapped argument list may run past its callee. */
const MAX_CONTINUATION_LINES = 3;

/** The statement a call sits in, with the two things reading it needs: which
 *  characters are inside a string literal, and which parentheses pair up. */
interface Statement {
  /** Comment-free text, continuation lines joined by a space. */
  text: string;
  /** 1 where `text[i]` is part of a string literal (its quotes included). */
  quoted: Uint8Array;
  /** For every `(` and `)` that pairs up inside the window, the index of its
   *  partner; -1 everywhere else, including a bracket the window never closes. */
  partner: Int32Array;
}

const EMPTY_STATEMENT: Statement = { text: "", quoted: new Uint8Array(0), partner: new Int32Array(0) };

/**
 * Index the window once: literals, and paren pairs that skip literals.
 *
 * Both are needed to cut a segment honestly. `foo(")")` balances only if the
 * scan knows that `)` is text, and the algorithm name `refutedBy` looks for is
 * itself inside a literal, so the literals cannot simply be dropped the way the
 * comments were.
 */
function analyzeStatement(text: string): Statement {
  const quoted = new Uint8Array(text.length);
  const partner = new Int32Array(text.length).fill(-1);
  const open: number[] = [];
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      quoted[i] = 1;
      if (ch === "\\") {
        i++;
        if (i < text.length) quoted[i] = 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      quoted[i] = 1;
      continue;
    }
    if (ch === "(") open.push(i);
    else if (ch === ")") {
      const start = open.pop();
      if (start !== undefined) {
        partner[start] = i;
        partner[i] = start;
      }
    }
  }
  return { text, quoted, partner };
}

/** The statement starting at `line` (1-based), or an empty one when the file has
 *  no such line. */
function statementAt(lines: readonly string[], line: number, langId: string): Statement {
  const first = lines[line - 1];
  if (first === undefined) return EMPTY_STATEMENT;
  const hash = HASH_COMMENT_LANGS.has(langId);
  const head = scanStatementLine(first, hash);
  let clean = head.clean;
  let depth = head.net;
  for (let i = 1; depth > 0 && i <= MAX_CONTINUATION_LINES; i++) {
    const next = lines[line - 1 + i];
    if (next === undefined) break;
    const cont = scanStatementLine(next, hash);
    clean += ` ${cont.clean}`;
    depth += cont.net;
  }
  return analyzeStatement(clean);
}

/** Characters that can appear inside a callee or receiver name. `$` is one in
 *  Java, JS and PHP; dropping a PHP sigil only ever shortens a prefix. */
const NAME_CHAR = /[A-Za-z0-9_$]/;

/** One occurrence of the callee, used as a call, inside a statement. */
interface Occurrence extends CallSite {
  /** The plain identifier this call hangs off (`Cipher` in
   *  `javax.crypto.Cipher.getInstance(…)`), or undefined when it hangs off a
   *  call (`…getInstance("SHA1PRNG").nextInt()`) or off nothing at all. That is
   *  what the extractor puts in `Call.receiver`, so the two compare directly. */
  receiver?: string;
}

/** The two parts of a matched call a refutation is allowed to read. Everything
 *  else about the call — the callee, the rest of the statement — is not
 *  evidence about it. */
interface CallSite {
  /** The receiver/construction chain the call hangs off, up to but not including
   *  the callee, read as structure rather than as text. */
  chain: ChainShape;
  /** One entry per top-level argument: the argument's value when the WHOLE
   *  argument is a single string literal, undefined otherwise (a variable, a
   *  concatenation, a nested call). Undefined for the list itself when it does
   *  not close inside the window, i.e. when the arguments were cut off. */
  literals?: (string | undefined)[];
}

/** Index of the first non-blank character at or before `i - 1` — the end of the
 *  token preceding `i`. */
function trimBack(text: string, i: number): number {
  let p = i;
  while (p > 0 && (text[p - 1] === " " || text[p - 1] === "\t")) p--;
  return p;
}

/** Index of the first non-blank character at or after `i`. */
function trimForward(text: string, i: number): number {
  let p = i;
  while (p < text.length && (text[p] === " " || text[p] === "\t")) p++;
  return p;
}

/** One link of a receiver chain: a name, and whether that name was applied to an
 *  argument list. `SecureRandom.getInstance("SHA1PRNG")` is two links — a plain
 *  `SecureRandom`, then a called `getInstance`. */
interface ChainLink {
  name: string;
  called: boolean;
}

/**
 * The chain a call hangs off, read as structure: the dotted names between the
 * start of the expression and the callee, head first.
 *
 * A chain is only ever evidence about provenance when the reader can say what
 * built the value, so anything it cannot resolve to a name — a parenthesized
 * expression, a cast, an index, an operator, a literal — sets `opaque`, and an
 * opaque chain proves nothing no matter what names survived beside it.
 */
interface ChainShape {
  /** The links, from the head of the expression to the one the callee hangs off. */
  links: ChainLink[];
  /** Some part of the chain is not a name or a call on a name. */
  opaque: boolean;
  /** The whole chain is a `new` expression. On the JVM that is the difference
   *  between constructing a type and invoking a method that shares its name —
   *  `new SecureRandom()` and `SecureRandom()` are different declarations, and
   *  only the first is a type at all. */
  newed: boolean;
}

/**
 * Walk back from the callee over its receiver chain: `a.b().c.callee` → back to
 * `a`. The dotted qualifier matters because the rule spells the receiver the way
 * the JDK does (`KeyGenerator.getInstance`) while the source spells it
 * `javax.crypto.KeyGenerator.getInstance`; the chained call matters because
 * `SecureRandom.getInstance("SHA1PRNG").nextInt()` is where the proof that a
 * draw is cryptographic actually sits.
 *
 * Anything that is not a chain link — `=`, `;`, `,`, `(`, `[`, a bare space —
 * stops the walk, so a chain cannot grow into the statement beside it.
 *
 * `new` is not a link — it qualifies the whole chain — so the walk stops at it
 * and records it on the shape. `new SecureRandom()` and `SecureRandom()` come
 * back as the same one called link, distinguished by `newed`; on the JVM that is
 * exactly the difference between a constructor and a method of the same name.
 */
function readChain(st: Statement, calleeAt: number): { receiver?: string; chain: ChainShape } {
  const { text } = st;
  let p = calleeAt;
  let receiver: string | undefined;
  let steps = 0;
  const links: ChainLink[] = [];
  let opaque = false;
  for (;;) {
    let q = trimBack(text, p);
    if (q === 0 || text[q - 1] !== "." || st.quoted[q - 1]) break;
    q--; // past the dot
    if (q > 0 && text[q - 1] === "?") q--; // `a?.b()`
    q = trimBack(text, q);
    if (q > 0 && text[q - 1] === ")" && st.partner[q - 1]! >= 0) {
      // A call in the chain: swallow its whole `(…)` group AND the callee that
      // opened it (`…SecureRandom.getInstance("SHA1PRNG").nextInt()`), then keep
      // walking from there. Its own receiver is picked up by the next turn.
      const inner = st.partner[q - 1]!;
      let name = inner;
      while (name > 0 && NAME_CHAR.test(text[name - 1]!) && !st.quoted[name - 1]) name--;
      // No name in front of the group: it is a parenthesized EXPRESSION, not a
      // call — a ternary, a cast, a grouped construction. Whatever is inside it
      // was selected by code this reader is not evaluating.
      if (name === inner) opaque = true;
      else links.unshift({ name: text.slice(name, inner), called: true });
      p = name < inner ? name : inner;
      steps++;
      continue;
    }
    let s = q;
    while (s > 0 && NAME_CHAR.test(text[s - 1]!) && !st.quoted[s - 1]) s--;
    if (s === q) {
      // A dot whose left side is not a name: an index (`pool[0].`), a literal,
      // an operator. The links already collected hang off something unreadable.
      opaque = true;
      break;
    }
    if (steps === 0) receiver = text.slice(s, q);
    links.unshift({ name: text.slice(s, q), called: false });
    p = s;
    steps++;
  }
  return { receiver, chain: { links, opaque, newed: links.length > 0 && keywordBefore(st, p) === "new" } };
}

/** The bare word immediately preceding `at`, or `""` when what precedes is not a
 *  word (an operator, a bracket, the start of the statement, a literal). */
function keywordBefore(st: Statement, at: number): string {
  const { text } = st;
  const end = trimBack(text, at);
  let start = end;
  while (start > 0 && NAME_CHAR.test(text[start - 1]!) && !st.quoted[start - 1]) start--;
  return text.slice(start, end);
}

/**
 * What the FILE says about the names a chain uses. An identity claim is settled
 * by scope: which names the file imported, and which ones it could be using for
 * something else entirely.
 */
interface RefutationContext {
  langId: string;
  /** Is `spec` one of the file's import specifiers? False whenever the imports
   *  were never extracted — "could not see them" is not "there are none", and an
   *  unprovable identity keeps the candidate either way. */
  imported(spec: string): boolean;
  /** Does the FILE declare a TYPE by this name? Such a declaration outranks a
   *  single-type import of the same simple name. */
  declaresType(name: string): boolean;
  /** Is this name written, somewhere in the file, as anything other than the
   *  qualifier of a dotted name? See `usedOnlyAsQualifier`. */
  usedOnlyAsQualifier(name: string): boolean;
}

/** `name` as a regex literal. Chain links and catalog names are identifiers, so
 *  `$` (legal in Java/JS/PHP) is the only metacharacter that can reach here. */
const asLiteral = (name: string) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Does the file declare a TYPE by this name?
 *
 * The one binding that outranks a single-type import of the same simple name: a
 * `class SecureRandom extends Random`, nested or not, makes every unqualified
 * `new SecureRandom()` below it that class. The extractor reports only top-level
 * types, so this reads the declaration keywords out of the source instead —
 * anchored to the declaration syntax and to this one name, and only ever able to
 * KEEP a candidate the import would otherwise have refuted.
 */
function declaresTypeNamed(lines: readonly string[], name: string): boolean {
  const decl = new RegExp(`(?:^|[^\\w$.])(?:class|interface|enum|record|trait|object|struct)\\s+${asLiteral(name)}(?![\\w$])`);
  return lines.some((l) => decl.test(l));
}

/**
 * Is this name only ever a QUALIFIER in this file — always immediately followed
 * by the dot of a dotted name?
 *
 * This is the check that keeps a package root honest. `java` and `javax` are
 * ordinary identifiers: a local, a parameter or a field of that name obscures the
 * package in every expression it is in scope for, and then
 * `java.security.SecureRandom.getInstance(…)` is a walk over somebody's object
 * graph that happens to spell the JDK. Such a binding has to WRITE the bare name
 * at its declaration (`Fakes java = …`, `catch (E javax)`, `f(Object java)`),
 * while a package root used as a package is written `java.` every single time.
 * So "the bare name never appears undotted" is a sound over-approximation of "no
 * binding shadows it": it cannot miss a binding the file makes, and the cases it
 * gets wrong — the name inside a comment or a string — only KEEP a candidate.
 *
 * Ordinary import and package declarations are skipped: they end in an undotted
 * name and bind no variable. `import static` is read instead of skipped — it binds
 * a field or a method into the file's scope under exactly that simple name, which
 * is a rebinding this check exists to catch.
 *
 * It answers "no" for essentially every simple TYPE name, because declaring a
 * variable of that type (`Cipher c = …`) writes it undotted. That is intended:
 * an unqualified type name in expression position genuinely is unprovable here.
 */
const IMPORT_LINE = /^\s*(?:import|package|from)\b/;
/** A JVM static import, and the simple name it binds (`*` for the on-demand form). */
const STATIC_IMPORT = /^\s*import\s+static\s+[\w$.]*?([\w$]+|\*)\s*;/;
function usedOnlyAsQualifierIn(lines: readonly string[], name: string): boolean {
  const use = new RegExp(`(?:^|[^\\w$.])${asLiteral(name)}(?![\\w$])\\s*(.?)`, "g");
  for (const line of lines) {
    // A static import binds its LAST segment — a field or a method — into the
    // file's scope, and the on-demand form binds names this reader cannot list.
    // The bare-name scan below would miss it: there the name is dotted.
    const stat = STATIC_IMPORT.exec(line);
    if (stat) {
      if (stat[1] === "*" || stat[1] === name) return false;
      continue;
    }
    if (IMPORT_LINE.test(line)) continue;
    use.lastIndex = 0;
    for (let m = use.exec(line); m; m = use.exec(line)) if (m[1] !== ".") return false;
  }
  return true;
}

/**
 * Is the type at `links[typeAt]` the one `t` describes, and not something else
 * wearing its simple name? `typeContext` is true where the language resolves the
 * name as a TYPE — after `new` — and variables therefore cannot obscure it.
 *
 * Qualified, the qualifier has to BE the type's namespace, exactly and entirely:
 * `evil.SecureRandom` and `fake.SecureRandom.getInstance` are somebody's own
 * class, and a prefix of the real path (`security.SecureRandom`) is not the path.
 * Unqualified, the only proof is the one import that binds that simple name.
 * Either way the ROOT of what was written has to still mean what it spells: no
 * type of that name declared in this file, and — outside type context — no use of
 * that name anywhere in the file that could be a binding.
 */
function identityProven(t: TrustedType, links: readonly ChainLink[], typeAt: number, ctx: RefutationContext, typeContext: boolean): boolean {
  if (!appliesTo(t.languages, ctx.langId)) return false;
  if (links[typeAt]?.name !== t.name) return false;
  for (let i = 0; i < typeAt; i++) if (links[i]!.called) return false;
  if (typeAt === 0) {
    if (t.simpleImport === undefined || !ctx.imported(t.simpleImport)) return false;
  } else {
    if (typeAt !== t.namespace.length) return false;
    for (let i = 0; i < typeAt; i++) if (links[i]!.name !== t.namespace[i]) return false;
  }
  const head = links[0]!.name;
  if (ctx.declaresType(head)) return false;
  return typeContext || ctx.usedOnlyAsQualifier(head);
}

/**
 * Does this chain PROVE the value came out of the API the rule names?
 *
 * The whole chain — never a fragment of it — has to be a construction of a
 * trusted type or a static factory called ON one, with every link before the type
 * a plain qualifier: a call there produced a value this reader knows nothing about
 * (`getFactory().getInstance("SHA1PRNG")` names the right factory on the wrong
 * owner). Then `identityProven` has to say the name is that type's.
 */
function chainProves(types: readonly TrustedType[], chain: ChainShape, ctx: RefutationContext): boolean {
  const { links, opaque, newed } = chain;
  if (opaque || links.length === 0) return false;
  const last = links[links.length - 1]!;
  // `new Q.T(…)`: the construction IS the type, and `new` reads it in type
  // context, where no variable can obscure the name.
  if (newed) return last.called && types.some((t) => identityProven(t, links, links.length - 1, ctx, true));
  // `Q.T.factory(…)`: an expression, so every name in it has to survive scope.
  if (!last.called || links.length < 2) return false;
  return types.some((t) => t.factories?.includes(last.name) && identityProven(t, links, links.length - 2, ctx, false));
}

/**
 * Which trusted type this call's RECEIVER is, for an `argument` refutation, or
 * undefined when the chain does not prove one.
 *
 * The chain has to be the type's name and nothing more — `javax.crypto.Cipher`
 * before a `.getInstance(…)`, every link a plain qualifier. It is an expression,
 * so the same scope test applies: `evil.Cipher` is the wrong namespace and a
 * file-local `class Cipher` outranks the import.
 */
function receiverType(types: readonly TrustedType[], chain: ChainShape, ctx: RefutationContext): TrustedType | undefined {
  const { links, opaque, newed } = chain;
  if (opaque || newed || links.length === 0 || links[links.length - 1]!.called) return undefined;
  return types.find((t) => identityProven(t, links, links.length - 1, ctx, false));
}

/**
 * The top-level arguments between `open` and `close`, each reduced to its string
 * value when the whole argument is one literal and to undefined when it is
 * anything else.
 *
 * Splitting is depth-aware over brackets and blind inside literals, so a comma in
 * `pick("a,b", c)` does not split and a nested `f(x, y)` stays one argument. A
 * split this reader gets wrong — Java generics carry commas too — can only make
 * an argument look non-literal, which keeps the candidate.
 */
function argumentLiterals(st: Statement, open: number, close: number): (string | undefined)[] {
  const { text, quoted } = st;
  const args: (string | undefined)[] = [];
  /** An argument is a literal exactly when every character in it, quotes
   *  included, is inside one — `"a" + b` and `f("a")` both have characters that
   *  are not, and adjacent literals need an unquoted separator between them. */
  const literalOf = (from: number, to: number): string | undefined => {
    const a = trimForward(text, from);
    const b = trimBack(text, to);
    if (b - a < 2 || !quoted[a]) return undefined;
    for (let i = a; i < b; i++) if (!quoted[i]) return undefined;
    return text.slice(a + 1, b - 1);
  };
  let depth = 0;
  let from = open + 1;
  for (let i = from; i < close; i++) {
    if (quoted[i]) continue;
    const ch = text[i]!;
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) {
      args.push(literalOf(from, i));
      from = i + 1;
    }
  }
  if (trimForward(text, from) < close) args.push(literalOf(from, close));
  return args;
}

/** More occurrences than this on one line and the answer is "ambiguous" anyway. */
const MAX_OCCURRENCES = 8;

/**
 * The one call in `st` that `callee`/`receiver` identify, or undefined when no
 * single call can be picked out.
 *
 * Undefined is the answer whenever attribution is in doubt, and the caller reads
 * it as "do not refute": no occurrence at all (the extractor matched a call this
 * reader cannot find in the text), several that the receiver cannot separate, or
 * a receiver that contradicts the only occurrence — a `Cipher` record against a
 * lone `MessageDigest.getInstance` is not that record's call.
 */
function callSiteFor(st: Statement, callee: string, receiver?: string): CallSite | undefined {
  const { text } = st;
  if (!callee || !text) return undefined;
  const found: Occurrence[] = [];
  for (let i = text.indexOf(callee); i >= 0; i = text.indexOf(callee, i + 1)) {
    if (st.quoted[i]) continue;
    const before = text[i - 1];
    if (before !== undefined && (NAME_CHAR.test(before) || before === "?")) continue;
    const end = i + callee.length;
    const after = text[end];
    if (after !== undefined && NAME_CHAR.test(after)) continue;
    const paren = trimForward(text, end);
    if (text[paren] !== "(" || st.quoted[paren]) continue; // a mention, not a call
    const { receiver: own, chain } = readChain(st, i);
    const close = st.partner[paren]!;
    // An argument list that never closes inside the window is a call whose
    // arguments were cut off: the chain still speaks for it, the arguments
    // cannot.
    found.push({ chain, literals: close >= 0 ? argumentLiterals(st, paren, close) : undefined, receiver: own });
    if (found.length > MAX_OCCURRENCES) return undefined;
  }
  if (found.length === 0) return undefined;
  let only = found[0]!;
  if (found.length > 1) {
    // With no column on the record, the receiver is the only discriminator left,
    // and it has to single one out. A tie is an unattributable refutation.
    if (!receiver) return undefined;
    const named = found.filter((o) => o.receiver === receiver);
    if (named.length !== 1) return undefined;
    only = named[0]!;
  } else if (receiver !== undefined && only.receiver !== undefined && only.receiver !== receiver) return undefined;
  return only;
}

/** Does this call show, structurally, that the rule does not apply to it? */
function refutes(rule: SinkRefutation, site: CallSite, ctx: RefutationContext): boolean {
  if (rule.by === "receiver") return chainProves(rule.types, site.chain, ctx);
  // The literal speaks for the call only once the chain has proven WHOSE
  // `getInstance` this is: a strong transformation handed to `evil.Cipher`, or to
  // a `Cipher` the file declares itself, says nothing about what that call does.
  const type = receiverType(rule.types, site.chain, ctx);
  const literal = site.literals?.[rule.index];
  return type?.safe !== undefined && literal !== undefined && type.safe.test(literal.trim());
}

/** Severity an `ambiguous` rule falls back to when nothing corroborated it. A
 *  candidate worth a second look, not a headline. */
const UNRESOLVED_SEVERITY: Severity = "medium";
export const UNRESOLVED_RECEIVER = "unresolved-receiver";

// ── Lookup indexes ───────────────────────────────────────────────────────────
// Every matcher below used to scan its whole rule table for every call, line or
// sanitizer probe. The tables are static, so each is indexed once — by callee
// for the call sinks, by language for the line-shaped rules — and looked up
// from then on. Keyed on the IDENTITY of the rule array (a WeakMap), so a table
// that is rebuilt (a test that mutates `SINKS`, a per-run union) simply gets a
// fresh index, and the index never outlives the array it describes. Iteration
// order inside a bucket is the table's own, which is what keeps "first
// matching rule wins" meaning the same rule as before.

const sinkIndexes = new WeakMap<readonly SinkRule[], Map<string, SinkRule[]>>();

/** `callee → rules naming it`, in table order. */
function sinkIndex(rules: readonly SinkRule[]): Map<string, SinkRule[]> {
  let idx = sinkIndexes.get(rules);
  if (!idx) {
    idx = new Map();
    for (const rule of rules) {
      for (const callee of rule.callees) {
        let bucket = idx.get(callee);
        if (!bucket) idx.set(callee, (bucket = []));
        bucket.push(rule);
      }
    }
    sinkIndexes.set(rules, idx);
  }
  return idx;
}

// `[...SINKS, ...extraSinks]` is rebuilt per call; memoized on the extras'
// identity so the union — and therefore its index — is stable across a run.
const mergedSinkTables = new WeakMap<readonly SinkRule[], SinkRule[]>();
function mergedSinks(extraSinks: SinkRule[]): SinkRule[] {
  let merged = mergedSinkTables.get(extraSinks);
  if (!merged) mergedSinkTables.set(extraSinks, (merged = [...SINKS, ...extraSinks]));
  return merged;
}

/** Per-language view of a line-shaped rule table (`*` rules included), table order kept. */
function byLanguage<R extends { languages: string[] }>(store: WeakMap<readonly R[], Map<string, R[]>>, rules: readonly R[], langId: string): R[] {
  let perLang = store.get(rules);
  if (!perLang) store.set(rules, (perLang = new Map()));
  let bucket = perLang.get(langId);
  if (!bucket) perLang.set(langId, (bucket = rules.filter((r) => appliesTo(r.languages, langId))));
  return bucket;
}

const textSinkByLang = new WeakMap<readonly TextSinkRule[], Map<string, TextSinkRule[]>>();
const sourceByLang = new WeakMap<readonly SourceRule[], Map<string, SourceRule[]>>();
const sanitizerByLang = new WeakMap<readonly SanitizerRule[], Map<string, SanitizerRule[]>>();

/**
 * @param extraSinks Additional rules unioned in for this call ONLY (e.g.
 * `LOG_SINKS` under `scan --log-hygiene`). Omitted/empty ⇒ matches exactly
 * `SINKS`, byte-identical to before this param existed.
 * @param imports The file's import specifiers, for `requireModule` and for
 * corroborating an `ambiguous` rule.
 * @param localDefs Callables the file DEFINES itself. A receiver-less call to
 * one of them is that function, not the catalog's — an application `run()`
 * declared 68 lines above its call site is not `subprocess.run`. Consulted by
 * `ambiguous` rules only (see the gate below for why). Omitted ⇒ no
 * local-definition gate, byte-identical to before this param existed.
 * @param lines The file's lines, for `refutedBy`. Only rules that declare one
 * read them, and only for the statement they matched. Omitted ⇒ no refutation
 * gate, byte-identical to before this param existed.
 */
export function findSinks(
  lang: LangSpec,
  calls: Call[],
  extraSinks?: SinkRule[],
  imports?: readonly { spec: string }[],
  localDefs?: ReadonlySet<string>,
  lines?: readonly string[],
): SinkHit[] {
  const byCallee = sinkIndex(extraSinks && extraSinks.length ? mergedSinks(extraSinks) : SINKS);
  const out: SinkHit[] = [];
  const specs = (imports ?? []).map((i) => i.spec.toLowerCase());
  // One parsed statement per line that needs one — several rules can consult the
  // same call, and a file has few crypto/RNG calls but many lines.
  const source = lines ?? [];
  const statements = new Map<number, Statement>();
  const statement = (line: number): Statement => {
    let st = statements.get(line);
    if (st === undefined) statements.set(line, (st = statementAt(source, line, lang.id)));
    return st;
  };
  // What the file says about the names a refutation reads. Exact specs, not the
  // lowercased `specs` above: `requireModule` asks whether a technology is
  // present, this asks whether one specific declaration is, and only the exact
  // spelling answers that. `imports` undefined ⇒ nothing is proven, which keeps
  // every candidate. Both name questions scan the file, so both memoize.
  const importSpecs = imports && new Set(imports.map((i) => i.spec));
  const memo = <T>(f: (name: string) => T) => {
    const seen = new Map<string, T>();
    return (name: string): T => {
      let v = seen.get(name);
      if (v === undefined) seen.set(name, (v = f(name)));
      return v;
    };
  };
  const refutationCtx: RefutationContext = {
    langId: lang.id,
    imported: (spec) => importSpecs?.has(spec) === true,
    declaresType: memo((name) => localDefs?.has(name) === true || declaresTypeNamed(source, name)),
    usedOnlyAsQualifier: memo((name) => usedOnlyAsQualifierIn(source, name)),
  };
  for (const c of calls) {
    // Only the rules naming this callee, in catalog order — the linear scan of
    // ~150 rules per call was the taint pass's second-hottest loop. Order is
    // preserved, so "first matching rule wins" below means the same rule.
    const rules = byCallee.get(c.callee);
    if (!rules) continue;
    // A call to a name this file defines resolves to that definition, whatever
    // the catalog thinks the name means. Applied to `ambiguous` rules only, and
    // for a reason worth stating: "no receiver" does NOT mean "bare call". The
    // extractor reports a receiver only when it is a plain identifier, so
    // `client.collection("users").find(filter)` — a chained call — arrives here
    // receiver-less too. Gating every rule on local definitions therefore
    // silenced a real NoSQL sink in a data-access wrapper that named its own
    // function `find`. Ambiguous rules already require corroboration; this is
    // one more piece of it, and the only place the trade is worth making.
    const shadowed = !c.receiver && localDefs?.has(c.callee) === true;
    // This call, read out of its statement — resolved once per call, on the first
    // rule that asks for it, and undefined when no single call on the line can be
    // attributed to this record.
    let site: CallSite | undefined;
    let siteRead = false;
    for (const rule of rules) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      // Verb-shaped callees (get/post/…) are only a sink as a MEMBER call
      // (`axios.get`) — a bare `get(x)` is a generic getter, so skip it.
      if (rule.requireReceiver && !c.receiver) continue;
      // If the rule pins receivers and this call has a *different* known one, skip
      // it (cuts false positives like `arr.call(...)` matching the command rule).
      // Rules with no `receivers` (e.g. sql) match any receiver.
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
      // The evidence gate: this call's own arguments or receiver chain say it is
      // not what the rule claims. Needs the file's lines; without them the rule
      // fires exactly as before, and so does a call that cannot be attributed.
      if (rule.refutedBy && lines) {
        if (!siteRead) {
          site = callSiteFor(statement(c.line), c.callee, c.receiver);
          siteRead = true;
        }
        if (site !== undefined && refutes(rule.refutedBy, site, refutationCtx)) continue;
      }
      // Technology gate. Only enforced when imports were actually extracted:
      // an empty list means we couldn't see them, not that there are none.
      // `specs` is lowercased, so the needle must be too — otherwise a rule
      // naming a capitalised module (`System.Diagnostics`, `java.lang.Runtime`)
      // can never match and silently stops firing.
      const moduleSeen = !!rule.requireModule && rule.requireModule.some((m) => specs.some((s) => s.includes(m.toLowerCase())));
      if (rule.requireModule && specs.length && !moduleSeen) continue;
      // Corroboration gate for `ambiguous` rules.
      let downgraded: string | undefined;
      if (rule.ambiguous && !(c.receiver && rule.receivers?.includes(c.receiver))) {
        // A local definition outranks the import. A file that declares `run`
        // and then calls `run(x)` is calling ITS `run`, even if the same file
        // imports `subprocess` for use elsewhere — shadowing is a language rule,
        // not a hint. (Only a receiver could say otherwise, and a call with a
        // receiver is never `shadowed`.)
        if (shadowed) continue;
        // Otherwise the import decides. Without one, it turns on whether imports
        // were VISIBLE at all — see the `ambiguous` doc comment.
        if (!moduleSeen) {
          if (specs.length) continue;
          downgraded = UNRESOLVED_RECEIVER;
        }
      }
      out.push({
        line: c.line,
        callee: c.callee,
        receiver: c.receiver,
        kind: rule.kind,
        cwe: rule.cwe,
        severity: downgraded ? UNRESOLVED_SEVERITY : rule.severity,
        title: rule.title,
        note: rule.note,
        ...(downgraded ? { downgraded } : {}),
      });
      break; // first matching rule wins
    }
  }
  return out;
}

// ── Sources ───────────────────────────────────────────────────────────────
export interface SourceRule {
  kind: string;
  languages: string[];
  re: RegExp;
  title: string;
}

export const SOURCES: SourceRule[] = [
  {
    kind: "http",
    languages: ["javascript"],
    re: /(?<![\w.])req(?:uest)?\s*\.\s*(?:query|body|rawBody|params|headers|cookies|method|url|originalUrl|hostname|ip|files|file)\b/,
    title: "HTTP request input",
  },
  { kind: "ws", languages: ["javascript"], re: /\.on\s*\(\s*['"](?:message|data)['"]/, title: "WebSocket/stream message" },
  { kind: "http", languages: ["javascript"], re: /\bctx\s*\.\s*(?:request|query|params|body)\b/, title: "Koa/HTTP context input" },
  // ── Handler SIGNATURES ────────────────────────────────────────────────────
  // The request/response parameter pair is the one shape every HTTP framework
  // in a given language agrees on, so matching the signature covers Express,
  // Koa, Fastify, Next, Nuxt and hand-rolled servers with one rule instead of
  // one per framework. It also catches the handler whose body never names
  // `req.query` — it destructures, reads `params`, or forwards `req` whole —
  // which is precisely the handler a line-content scan cannot see.
  {
    kind: "http",
    languages: ["javascript"],
    // `(req, res)`, `(req: NextApiRequest, res: NextApiResponse)`,
    // `(request, reply)`. The type annotation is optional and skipped, so this
    // is not tied to any one framework's types.
    //
    // A LEADING UNDERSCORE on the request parameter is honoured as what it
    // universally means — deliberately unused. `(_req, res)` is the author
    // saying this handler reads nothing from the request, so it is not a live
    // entry point, and treating it as one would tell the taint walk that a
    // constant-command handler shares a scope with untrusted input.
    re: /\(\s*(?:req|request)\w*\s*(?::[^,)]+)?\s*,\s*_?(?:res|response|reply)\w*\s*(?::[^,)]+)?\s*[,)]/,
    title: "HTTP handler signature (request/response pair)",
  },
  {
    kind: "http",
    languages: ["javascript", "python", "ruby"],
    // AWS Lambda / Azure / GCP: `(event, context)` and `(event)` on an exported
    // handler. Kept to the two-arg form so an ordinary `on(event)` callback in
    // application code is not mistaken for an internet-facing entry point.
    re: /\(\s*event\s*(?::[^,)]+)?\s*,\s*_?(?:context|ctx|callback)\s*(?::[^,)]+)?\s*[,)]/,
    title: "Serverless handler signature (event/context)",
  },
  {
    kind: "http",
    languages: ["go"],
    re: /\(\s*\w+\s+http\.ResponseWriter\s*,\s*\w+\s+\*http\.Request\s*\)/,
    title: "net/http handler signature",
  },
  {
    kind: "http",
    languages: ["java", "kotlin", "scala", "csharp"],
    re: /\b(?:HttpServletRequest|HttpRequest|HttpRequestMessage|ServerRequest)\s+\w+/,
    title: "Servlet/HTTP handler signature",
  },
  {
    kind: "http",
    languages: ["python"],
    // `def view(request)` / `def get(self, request)` — the Django/DRF shape,
    // where the request object is a positional parameter and the body may never
    // spell out `request.GET`.
    re: /\bdef\s+\w+\s*\(\s*(?:self\s*,\s*|cls\s*,\s*)?request\b/,
    title: "Django/DRF view signature",
  },
  {
    kind: "http",
    languages: ["python"],
    re: /(?<![\w.])request\s*\.\s*(?:args|form|values|json|data|files|cookies|headers|GET|POST)\b/,
    title: "HTTP request input",
  },
  { kind: "http", languages: ["php"], re: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/, title: "HTTP superglobal input" },
  {
    // Measured on OWASP Benchmark: 664 of 2740 cases (24%) read their untrusted
    // input from `request.getCookies()` alone. With only getParameter/getHeader
    // here, NO path could close in any of them — every class scored zero for want
    // of a source, not for want of a sink. A cookie is ordinary attacker-typed
    // input, and so is the request body, the URI and the path info.
    kind: "http",
    languages: ["java", "kotlin", "scala"],
    re: /\.get(?:Parameter(?:Values|Map|Names)?|Headers?|HeaderNames|QueryString|Cookies|InputStream|Reader|RequestURI|RequestURL|PathInfo|PathTranslated|RemoteUser|RemoteAddr|RemoteHost|RequestedSessionId|Parts?)\s*\(/,
    title: "Servlet request input",
  },
  // `theCookie.getValue()` — gated on a cookie-shaped receiver so a generic
  // `.getValue()` (a Map.Entry, an Optional) does not match.
  { kind: "http", languages: ["java", "kotlin", "scala"], re: /\b\w*[Cc]ookie\w*\s*\.\s*getValue\s*\(/, title: "Cookie value (attacker-controlled)" },
  { kind: "http", languages: ["ruby"], re: /(?<![\w.])params\s*\[/, title: "Rails params input" },
  { kind: "http", languages: ["go"], re: /\br\s*\.\s*(?:URL|FormValue|PostFormValue|Header)\b/, title: "net/http request input" },
  { kind: "cli", languages: ["javascript"], re: /\bprocess\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["python"], re: /\bsys\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["go"], re: /\bos\.Args\b/, title: "CLI argument" },
  { kind: "env", languages: ["javascript"], re: /\bprocess\.env\b/, title: "Environment variable" },
  { kind: "env", languages: ["python"], re: /\bos\.(?:environ|getenv)\b/, title: "Environment variable" },
  { kind: "env", languages: ["*"], re: /\bgetenv\s*\(/, title: "Environment variable" },
  { kind: "stdin", languages: ["python"], re: /\binput\s*\(/, title: "Interactive/stdin input" },

  // ── Client-side (DOM) ────────────────────────────────────────────────────
  // Everything the page can read that the attacker can set from a link. Paired
  // with TEXT_SINKS these close the DOM XSS loop, which the server-side `xss`
  // rules never touched.
  {
    kind: "dom",
    languages: ["javascript"],
    re: /\blocation\s*\.\s*(?:hash|search|href|pathname|host|hostname)\b|\bdocument\s*\.\s*(?:URL|documentURI|referrer|baseURI)\b|\bwindow\s*\.\s*name\b/,
    title: "URL / document input (attacker-set from a link)",
  },
  { kind: "dom", languages: ["javascript"], re: /\bnew\s+URLSearchParams\s*\(|\bdocument\s*\.\s*cookie\b/, title: "Query-string / cookie input" },
  {
    kind: "dom",
    languages: ["javascript"],
    re: /\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(|\bhistory\s*\.\s*state\b/,
    title: "Client-storage input (attacker-writable from any XSS)",
  },
  // A `message` listener without an origin check is CWE-346 in its own right;
  // the `event.data` it hands you is cross-origin attacker input either way.
  { kind: "postmessage", languages: ["javascript"], re: /\b(?:event|e|msg|ev)\s*\.\s*data\b/, title: "postMessage payload (cross-origin)" },

  // ── Web frameworks the catalog previously could not see ──────────────────
  // Without these a Spring Boot, ASP.NET, Actix, Phoenix or Gin repo yields a
  // link-graph and almost no entry surface — the engine looks clean by default
  // of detection, which is the worst way for it to be wrong.
  {
    kind: "http",
    languages: ["java", "kotlin", "scala"],
    re: /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|MatrixVariable)\b/,
    title: "Spring request binding",
  },
  { kind: "http", languages: ["java", "kotlin"], re: /\bcall\s*\.\s*(?:receive|parameters|request)\b/, title: "Ktor request input" },
  {
    kind: "http",
    languages: ["csharp"],
    re: /\bRequest\s*\.\s*(?:Query|Form|Headers|Cookies|Body|QueryString|Params|RouteValues)\b|\[From(?:Body|Query|Route|Form|Header)\]/,
    title: "ASP.NET request input",
  },
  { kind: "http", languages: ["rust"], re: /\b(?:Query|Path|Json|Form)\s*<|\bweb\s*::\s*(?:Query|Path|Json|Form)\b/, title: "axum/actix extractor" },
  { kind: "http", languages: ["elixir"], re: /\bconn\s*\.\s*(?:params|body_params|query_params|path_params|req_headers)\b/, title: "Phoenix conn input" },
  {
    kind: "http",
    languages: ["go"],
    re: /\bc\s*\.\s*(?:Param|Query|PostForm|DefaultQuery|GetHeader|ShouldBind|ShouldBindJSON|BindJSON|FormValue)\s*\(/,
    title: "gin/echo/fiber request input",
  },
  { kind: "http", languages: ["go"], re: /\bmux\s*\.\s*Vars\s*\(|\bchi\s*\.\s*URLParam\s*\(/, title: "gorilla/chi route parameter" },
  {
    kind: "http",
    languages: ["php"],
    re: /\$request\s*->\s*(?:input|query|get|post|all|json|header|cookie|file)\s*\(/,
    title: "Laravel/Symfony request input",
  },
  {
    kind: "http",
    languages: ["python"],
    re: /\b(?:Query|Body|Form|Path|Header|Cookie|File|UploadFile)\s*\(\s*(?:\.\.\.|None|default)/,
    title: "FastAPI parameter binding",
  },
  { kind: "http", languages: ["python"], re: /\brequest\s*\.\s*(?:query_params|path_params|body|stream|form\b)/, title: "Starlette/FastAPI request input" },
  { kind: "http", languages: ["javascript"], re: /@(?:Body|Query|Param|Headers|UploadedFile)\s*\(/, title: "NestJS parameter decorator" },
  {
    // Hono: `c.req.query("q")`, `c.req.param("id")`, `await c.req.json()`.
    kind: "http",
    languages: ["javascript"],
    re: /\b(?:c|ctx|context)\s*\.\s*req\s*\.\s*(?:query|queries|param|header|json|text|valid|raw|parseBody|formData|arrayBuffer|url|path)\b/,
    title: "Hono request input",
  },
  {
    // tRPC / oRPC procedures: everything after `.input(schema)` reads the
    // caller's input. The schema validates its SHAPE, not its safety.
    kind: "http",
    languages: ["javascript"],
    re: /\.\s*input\s*\(\s*(?:z\.|v\.|t\.|\w+Schema\b|\w+Input\b|\{)/,
    title: "tRPC/oRPC procedure input",
  },
  {
    // GraphQL resolvers: `(parent, args, ctx)` / `(_, { id })` — `args` is the
    // client's variables, whatever the schema says about their type.
    kind: "http",
    languages: ["javascript"],
    re: /\(\s*(?:parent|root|_|_parent|_root|obj|source)\w*\s*(?::[^,)]+)?\s*,\s*(?:args|_?input|\{[^}]*\})\s*(?::[^,)]+)?\s*[,)]/,
    title: "GraphQL resolver arguments",
  },
  {
    // Spring's mapping annotations mark the method below as an endpoint even
    // when it binds nothing by name (a `@RequestBody`-less POST reading
    // `HttpServletRequest` from a field, a `Map` parameter).
    kind: "http",
    languages: ["java", "kotlin", "scala"],
    re: /@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b/,
    title: "Spring request mapping",
  },
  {
    // Django REST framework: the decorated function IS the endpoint.
    kind: "http",
    languages: ["python"],
    re: /@api_view\s*\(|@action\s*\(|\bAPIView\b|\bViewSet\b/,
    title: "Django REST framework view",
  },
  {
    kind: "http",
    languages: ["javascript"],
    re: /\b(?:searchParams|nextUrl)\s*\.\s*get\s*\(|\bawait\s+(?:req|request)\s*\.\s*(?:json|formData|text)\s*\(/,
    title: "Next.js / fetch API request input",
  },
  {
    kind: "http",
    languages: ["swift"],
    re: /\bURLComponents\b[\s\S]{0,40}\bqueryItems\b|\breq\s*\.\s*(?:parameters|query|content)\b/,
    title: "Swift URL / Vapor request input",
  },
  { kind: "cli", languages: ["shell"], re: /\$\{?(?:[1-9]|@|\*)\b|\bread\s+(?:-[rp]\s+)*[A-Za-z_]/, title: "Shell positional argument / read" },
  {
    // ONLY the main-method parameter. Matching a bare `String[] args` caught every
    // local array a developer happened to name `args` — measured on OWASP
    // Benchmark, `String[] args = {sh, -c, cmd}` inside a request handler made the
    // whole file look attacker-controlled and produced 13 spurious candidates on
    // one safe case alone.
    kind: "cli",
    languages: ["java", "kotlin", "scala", "csharp"],
    re: /\b(?:static\s+(?:void|int)\s+[Mm]ain|fun\s+main|def\s+main)\s*\(/,
    title: "CLI argument (main)",
  },
  { kind: "cli", languages: ["rust"], re: /\benv\s*::\s*args\s*\(/, title: "CLI argument" },

  // ── Model output: attacker-INFLUENCED, not attacker-typed ────────────────
  // The direction that matters most and that no scanner models. Anything a model
  // read (a RAG document, a fetched page, a tool result) can steer what it
  // writes; if that output then reaches exec/SQL/fs, the prompt boundary is the
  // only thing standing between a web page and your shell.
  {
    kind: "llm",
    languages: ["*"],
    re: /\bchoices\s*\[\s*0\s*\]\s*\.\s*message\b|\.\s*(?:completion|generated_text|output_text)\b|\bmessage\s*\.\s*content\b|\bresponse\s*\.\s*(?:text|content|output)\b/,
    title: "Model output (attacker-influenced via prompt injection)",
  },
  {
    kind: "llm",
    languages: ["*"],
    re: /\b(?:llm|chain|agent|model)\s*\.\s*(?:invoke|run|predict|generate|complete)\s*\(/,
    title: "LLM/agent invocation result",
  },
];

export interface SourceHit {
  line: number;
  kind: string;
  match: string;
  title: string;
}

// ── Routes by convention ────────────────────────────────────────────────────
// `SOURCES` above is a line-content scan, and that is a blind spot no regex can
// close: in a file-system-routed framework the fact that makes a file an HTTP
// entry point is its PATH, not anything written inside it. A handler that never
// touches `req.query` — it destructures the body, reads `params`, or just passes
// `req` along — was invisible to `context`, `map`, the taint seeder and, through
// them, to `investigate`. Measured on a real Next.js admin app: 3 of 27 routes
// detected, and the region worklist for the whole authenticated surface empty.
//
// So this table is keyed on the path, and it is deliberately not per-framework:
// the labels are documentation, the mechanism is `files` × `decl`. Adding a new
// stack is a row, not a code path.
export interface RouteRule {
  /** Entry-point kind, as `SOURCES` uses it — "http" for everything here. */
  kind: string;
  /** Repo-relative globs the file must match (compiled with `globToRe`). */
  files: string[];
  /**
   * Which declaration lines are handlers. Omitted ⇒ `DEFAULT_HANDLER_DECL`, the
   * "any exported or default-exported function" fallback — which is the whole
   * point: in a routes directory, an exported function IS the endpoint, whatever
   * shape the declaration takes.
   */
  decl?: RegExp;
  /** What the convention is, for the scaffold and the report. */
  title: string;
}

/** Exported / default-exported / assigned callables, across ecosystems. The
 *  fallback for every routes directory that does not need something narrower. */
const DEFAULT_HANDLER_DECL =
  /^\s*(?:export\s+default\s+|export\s+|module\.exports\s*=|exports\.\w+\s*=|public\s+|def\s+|func\s+|fn\s+|sub\s+)|^\s*(?:async\s+)?function\s+\w|^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\(|function\b)/;

/** HTTP-verb named exports — the App-Router / Nitro / SvelteKit shape, where the
 *  export NAME is the method. Narrower than the default so a route module's
 *  helpers are not each reported as an endpoint. */
const VERB_EXPORT_DECL = /^\s*export\s+(?:async\s+)?(?:function\s+)?(?:const\s+)?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL|default)\b/;

export const ROUTE_FILES: RouteRule[] = [
  // ── File-system routers (JS/TS) ───────────────────────────────────────────
  { kind: "http", files: ["**/pages/api/**/*.{js,jsx,ts,tsx,mjs,cjs}", "pages/api/**/*.{js,jsx,ts,tsx,mjs,cjs}"], title: "Pages-Router API route" },
  { kind: "http", files: ["**/app/**/route.{js,ts,jsx,tsx}", "app/**/route.{js,ts,jsx,tsx}"], decl: VERB_EXPORT_DECL, title: "App-Router route handler" },
  { kind: "http", files: ["**/server/api/**/*.{js,ts}", "**/server/routes/**/*.{js,ts}"], title: "Nitro/Nuxt server route" },
  { kind: "http", files: ["**/routes/**/+server.{js,ts}"], decl: VERB_EXPORT_DECL, title: "SvelteKit endpoint" },
  { kind: "http", files: ["**/routes/**/+page.server.{js,ts}", "**/routes/**/*.server.{js,ts}"], title: "Server-side route module" },
  // ── Serverless / edge ─────────────────────────────────────────────────────
  { kind: "http", files: ["api/**/*.{js,ts,py,go,rb}", "**/netlify/functions/**/*.{js,ts}", "**/functions/**/*.{js,ts}"], title: "Serverless function" },
  { kind: "http", files: ["**/handler.{js,ts,py,rb}", "**/lambda_function.py", "**/*_handler.py"], title: "Serverless handler module" },
  // ── Controller conventions ────────────────────────────────────────────────
  { kind: "http", files: ["**/app/controllers/**/*.rb", "**/controllers/**/*.{js,ts,php,py,rb}"], title: "Controller action" },
  { kind: "http", files: ["**/*Controller.{java,kt,cs,php,ts}", "**/*_controller.rb"], title: "Controller action" },
  { kind: "http", files: ["**/views.py", "**/urls.py", "**/routes.py"], title: "Django view / URL module" },
  // ── PHP web roots: any reachable script is an entry point ──────────────────
  {
    kind: "http",
    files: ["{public,web,htdocs,www,public_html}/**/*.php", "**/{public,web,htdocs,www}/**/*.php"],
    decl: /^\s*<\?php/,
    title: "Web-root PHP script",
  },
  // ── Route tables ──────────────────────────────────────────────────────────
  // Laravel's `routes/web.php`/`routes/api.php` and Rails' `config/routes.rb`
  // hold no handler bodies, but every `Route::get(...)` / `get "/x", to:` line
  // names an endpoint — and a closure route (`Route::get('/u', function
  // (Request $r) {...})`) IS the handler.
  {
    kind: "http",
    files: ["routes/{web,api,channels,console}.php", "**/routes/{web,api}.php"],
    decl: /^\s*Route\s*::\s*\w+\s*\(/,
    title: "Laravel route declaration",
  },
  {
    kind: "http",
    files: ["config/routes.rb", "**/config/routes.rb", "**/config/routes/*.rb"],
    decl: /^\s*(?:get|post|put|patch|delete|match|resources?|root|mount|namespace|scope)\b/,
    title: "Rails route declaration",
  },
];

const routeMatchers = ROUTE_FILES.map((r) => ({ rule: r, res: r.files.flatMap(expandBraces).map(globToRe) }));

/**
 * Entry points a file has by CONVENTION — because of where it sits, not what it
 * says. Emitted in the same `SourceHit` shape as `findSources`, so every
 * consumer (attack surface, context scaffold, taint seeding) gets them for free.
 *
 * `rel` must be a repo-relative POSIX path.
 */
export function findRouteEntryPoints(rel: string, content: string): SourceHit[] {
  const matched = routeMatchers.filter((m) => m.res.some((re) => re.test(rel)));
  if (!matched.length) return [];
  const out: SourceHit[] = [];
  const lines = content.split(/\r?\n/);
  for (const { rule } of matched) {
    const decl = rule.decl ?? DEFAULT_HANDLER_DECL;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const m = decl.exec(line);
      if (m) out.push({ line: i + 1, kind: rule.kind, match: m[0].trim(), title: rule.title });
    }
  }
  // One entry point per line: two conventions can match the same path (an
  // `app/api/**/route.ts` is also under a `functions/**` glob on some layouts)
  // and the surface should count the endpoint once.
  const seen = new Set<number>();
  return out.sort((a, b) => a.line - b.line).filter((h) => (seen.has(h.line) ? false : (seen.add(h.line), true)));
}

/**
 * @param rel Repo-relative path. When given, entry points the file has by
 * ROUTE CONVENTION are unioned in — see `ROUTE_FILES`. Omitted ⇒ line-content
 * rules only, byte-identical to before this param existed.
 */
export function findSources(lang: LangSpec, content: string, rel?: string): SourceHit[] {
  const out: SourceHit[] = [];
  const lines = content.split(/\r?\n/);
  const rules = byLanguage(sourceByLang, SOURCES, lang.id);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of rules) {
      const m = rule.re.exec(line);
      if (m) out.push({ line: i + 1, kind: rule.kind, match: m[0], title: rule.title });
    }
  }
  if (rel) {
    // Don't double-report a line the content rules already claimed: a handler
    // that reads `req.query` on its declaration line is one entry point.
    const claimed = new Set(out.map((h) => h.line));
    for (const h of findRouteEntryPoints(rel, content)) if (!claimed.has(h.line)) out.push(h);
    out.sort((a, b) => a.line - b.line);
  }
  return out;
}

// ── Sanitizers (hints) ──────────────────────────────────────────────────────
export interface SanitizerRule {
  /** The sink kind this sanitizer addresses ("*" = general validation). */
  kind: string;
  languages: string[];
  re: RegExp;
  note: string;
  /**
   * The pattern is only evidence when it appears ON a sink line of this kind —
   * it says something about THAT statement, not about the file.
   *
   * `findSanitizers` always has a sink kind, so the distinction never mattered
   * there. The CONTEXT scaffold has no sink: it runs the catalog over every line
   * of every file to answer "which sanitizers does this project use?", and a
   * rule like the SQL placeholder test ("does this query look parameterized?")
   * answers that question with `foo?: string`, `key: value` and `@scope/pkg` —
   * 3% of every TypeScript line in a real repo.
   */
  sinkLineOnly?: boolean;
  /**
   * Sink kinds this rule must NOT speak for, even though it is a wildcard.
   *
   * The general-validation rule answers "is this value type-checked?", and for
   * nearly every sink that is evidence. For `algodos` it is the opposite of
   * evidence: the audited repository validated every route parameter with zod
   * and still shipped a remote CPU denial of service, because the schema said
   * `min(1)` and never said `max`. Reporting "type-coercion/validation present"
   * on that line would hand the adjudicator the exact reassurance the bug
   * depends on. What contains this class is an upper BOUND, and the `algodos`
   * rule below is the one that looks for it.
   */
  exceptKinds?: string[];
}

export const SANITIZERS: SanitizerRule[] = [
  // Placeholder shapes: meaningful ON a query line, meaningless anywhere else —
  // `?`, `:name` and `@scope` are ordinary TypeScript punctuation.
  { kind: "sql", languages: ["*"], re: /\?|\$\d+|:\w+|%s|@\w+/, note: "looks parameterized (placeholder present)", sinkLineOnly: true },
  // The BINDING calls, which follow the prepare on the next line or two —
  // `stmt.setString(1, name)`, `$stmt->bind_param("s", $x)`, `bindValue`,
  // PDO's `execute([...])`, ESAPI's SQL encoder. OWASP Benchmark scored 0 for
  // "FP w/ sanitizer noted" on CWE-89 because none of these was known.
  {
    kind: "sql",
    languages: ["*"],
    re: /\.\s*set(?:String|Int|Long|Object|Date|Timestamp|Boolean|Double|BigDecimal|Bytes)\s*\(|\bbind_?[Pp]aram\s*\(|\bbindValue\s*\(|\bexecute\s*\(\s*\[|\bexecute\s*\(\s*(?:array|\{)|encodeForSQL|\bsqlEscape|\bmysqli_real_escape_string\b|\bpg_escape_(?:string|literal)\b|\bquoteIdentifier\b|\bsanitize_sql\b/,
    note: "parameter binding / SQL escaping present",
  },
  // ActiveRecord's safe forms: the hash argument or the placeholder form.
  {
    kind: "sql",
    languages: ["ruby"],
    re: /\bwhere\s*\(\s*(?:\w+\s*:|\{|["'][^"']*\?)/,
    note: "hash / placeholder form of where (parameterized)",
    sinkLineOnly: true,
  },
  { kind: "command", languages: ["*"], re: /\bexecFile\b|\bexecvp?\b|shlex\.quote|escapeshellarg/, note: "argv-array / quoting present" },
  { kind: "path", languages: ["*"], re: /\bbasename\b|\brealpath\b|secure_filename|path\.resolve|startsWith\(/, note: "path-confinement helper present" },
  // `escape(?:Html)?\b` could not match the camelCase family (`escapeAttrValue`),
  // and nothing looked for the `xss` library at all — so on a repo whose only
  // HTML sanitizer is `xssWrapper` wrapping `xss@1.0.15`, the brief that exists
  // to answer "which sanitizers does this project use?" named none of it.
  { kind: "xss", languages: ["*"], re: /\bescape[A-Z]?\w*\b|sanitize|DOMPurify|bleach|markupsafe|\bxss[A-Za-z]*\b/, note: "escaping/sanitizer present" },
  // The JVM/.NET/Go encoders by name: ESAPI, OWASP Java Encoder, Spring's
  // HtmlUtils, Commons Text, ASP.NET's HttpUtility/HtmlEncoder, Go's html.
  {
    kind: "xss",
    languages: ["*"],
    re: /encodeForHTML(?:Attribute)?|encodeForJavaScript|encodeForCSS|encodeForURL|\bEncode\s*\.\s*for(?:Html|JavaScript|Css|Uri)\w*|HtmlUtils\s*\.\s*htmlEscape|StringEscapeUtils\s*\.\s*escape\w*|HttpUtility\s*\.\s*(?:HtmlEncode|JavaScriptStringEncode|UrlEncode)|HtmlEncoder\s*\.\s*(?:Default\s*\.\s*)?Encode|WebUtility\s*\.\s*HtmlEncode|\bhtml\s*\.\s*EscapeString|\bhtmlspecialchars\b|\bhtmlentities\b|\bERB\s*::\s*Util\s*\.\s*(?:html_escape|h)\b|\bsanitize_html\b/,
    note: "HTML output encoder present",
  },
  { kind: "deserialize", languages: ["*"], re: /safe_load|safeLoad|JSON\.parse/, note: "safe loader present" },
  { kind: "nosql", languages: ["*"], re: /mongo-?[sS]anitize|sanitizeFilter|\$eq\b/, note: "operator-stripping sanitizer present" },
  {
    kind: "xxe",
    languages: ["*"],
    re: /resolve_entities\s*=\s*False|feature_external_ges|FEATURE_SECURE_PROCESSING|noent\s*=\s*False|XMLConstants/,
    note: "external-entity resolution disabled",
  },
  {
    kind: "ldap",
    languages: ["*"],
    re: /ldap\.escape|escapeDN|escapeFilter|escape_filter_chars|encodeForLDAP|encodeForDN|LdapEncoder|\bldap_escape\b|Rdn\s*\.\s*escapeValue|LdapNameBuilder/,
    note: "LDAP escaping present",
  },
  // Destination allow-listing for redirects and outbound requests: a parsed
  // URL (`new URL(x)`) compared against an allowed host set, Django's
  // `url_has_allowed_host_and_scheme`, ASP.NET's `Url.IsLocalUrl`, a
  // relative-path check.
  {
    kind: "redirect",
    languages: ["*"],
    re: /\bnew\s+URL\s*\(|\bisSafeRedirect\b|\bis_safe_url\b|url_has_allowed_host_and_scheme|\bIsLocalUrl\b|\bLocalRedirect\b|\ballowedHosts?\b|\bALLOWED_HOSTS\b|\bstartsWith\s*\(\s*['"]\/(?!\/)/,
    note: "redirect destination validated (allow-list / local-path check present)",
  },
  {
    kind: "ssrf",
    languages: ["*"],
    re: /\bnew\s+URL\s*\(|\bURL\s*\.\s*parse\b|\burlparse\b|\ballowedHosts?\b|\bALLOWED_HOSTS\b|\ballow_?list\b|\bisPrivate(?:Ip|Address|Host)\b|\bip\s*\.\s*isPrivate\b|\bssrf/i,
    note: "destination parsed / allow-listed (SSRF guard present)",
  },
  // Argv-array runners that never spawn a shell, and quoting libraries.
  {
    kind: "command",
    languages: ["*"],
    re: /\bexeca\b|\bshell-quote\b|\bshellQuote\b|\bshlex\s*\.\s*(?:quote|split)\b|\bescapeshellcmd\b|\bspawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[|\bexecFile(?:Sync)?\s*\(/,
    note: "argv-array runner / shell quoting present",
  },
  { kind: "crlf", languages: ["*"], re: /encodeURIComponent|stripCRLF|replace\(\s*\/[^/]*[\\]r/, note: "CR/LF stripping present" },
  {
    kind: "proto",
    languages: ["*"],
    re: /__proto__|Object\.freeze|Object\.create\(\s*null|hasOwnProperty|structuredClone/,
    note: "prototype-pollution guard present",
  },
  {
    kind: "ssti",
    languages: ["*"],
    re: /autoescape|markupsafe|\|\s*e\b|escape\(|DOMPurify|\bSandboxedEnvironment\b|\bImmutableSandboxedEnvironment\b|\bEscapeTool\b|\bTemplateClassResolver\b/,
    note: "template autoescaping / sandbox present",
  },
  {
    kind: "domxss",
    languages: ["*"],
    re: /DOMPurify|\bsanitizeHtml\b|createPolicy|textContent\s*=|\bescapeHtml\b/,
    note: "HTML sanitizer / Trusted Types policy present",
  },
  {
    kind: "argv",
    languages: ["*"],
    re: /startsWith\(\s*['"]-|\breplace\(\s*\/\^-|\ballowlist\b|\ballowList\b|--\s*['"]?\s*,/,
    note: "option-injection guard present (leading '-' rejected or `--` terminator)",
  },
  { kind: "redos", languages: ["*"], re: /\bRE2\b|re2|\bescapeRegExp\b|\bescape_string\b|timeout/, note: "linear-time engine or pattern escaping present" },
  // What actually contains an algorithmic-DoS sink is an upper bound on the
  // input, so that is what this looks for — and NOT a minimum. `min(1)` /
  // `length >= 3` is the guard the audited repo had, and it bounds nothing.
  {
    kind: "algodos",
    languages: ["*"],
    re: /\.slice\s*\(\s*0\s*,|\.substring\s*\(\s*0\s*,|\.substr\s*\(\s*0\s*,|\bmax\s*\(\s*\d|\bmaxLength\b|\bmax_length\b|\blength\s*[<>]=?\s*\d|\btruncate\b|\[\s*:\s*\d+\s*\]/,
    note: "input length bounded (upper bound present)",
  },
  {
    kind: "reflect",
    languages: ["*"],
    re: /\bALLOWED\b|allowlist|allowList|\bin\s+\{|\bMap\s*\(|hasOwnProperty|\bdict\s*\[/,
    note: "allow-list lookup present",
  },
  {
    kind: "xpath",
    languages: ["*"],
    re: /setXPathVariable|XPathVariableResolver|\bbindVariable\b|\$\w+/,
    note: "XPath variable binding present",
    sinkLineOnly: true,
  },
  {
    kind: "massassign",
    languages: ["*"],
    re: /\bpick\b|\bfillable\b|\bpermit\b|\bonly\s*\(|\bwhitelist\b|\bz\.object|Joi\.object/,
    note: "explicit field allow-list present",
  },
  {
    kind: "csv",
    languages: ["*"],
    re: /startsWith\(\s*['"][=+\-@]|\bescapeFormula\b|\bsanitizeCell\b|['"]'\s*\+/,
    note: "formula-prefix neutralization present",
  },
  // Prompt-level "sanitizers" are weak by construction: nothing reliably
  // separates instructions from data inside a prompt. What actually contains the
  // class is restricting the model's OUTPUT — so that is what this looks for.
  {
    kind: "llm",
    languages: ["*"],
    re: /\ballowed_tools\b|\btool_choice\b|\ballowlist\b|\bschema\b|\bz\.object|\bJSON\.parse\b|\bvalidate\b/,
    note: "output constrained (schema / tool allow-list) — the only control that holds for this class",
  },
  {
    kind: "*",
    languages: ["*"],
    // The schema/validation libraries by name (zod, Joi, yup, ajv,
    // express-validator, class-validator, pydantic, marshmallow, Bean
    // Validation's @Valid) plus the type coercions. A schema says the value has
    // the right SHAPE — which is evidence for most sinks and none for `algodos`.
    // express-validator's `query('q')`/`param('id')` are deliberately absent:
    // `db.query("SELECT…")` has the same shape and would read as validated.
    re: /\bparseInt\b|\bNumber\(|\bInteger\.parse|\bLong\.parse|\bint\s*\(|validator\.|\bz\.|Joi\.|\byup\s*\.|\bajv\b|\bAjv\b|\bbody\s*\(\s*['"]|\bcheck\s*\(\s*['"]|validationResult|class-validator|\bpydantic\b|\bBaseModel\b|\bmarshmallow\b|@Valid\b|@Validated\b|\bisInt\b|\bUUID\b|\bmatches\s*\(\s*\/|\bPattern\s*\.\s*matches\b/,
    note: "type-coercion/validation present",
    exceptKinds: ["algodos"],
  },
];

/** Sanitizer hints found on a given line of code (for the candidate's note). */
export function findSanitizers(lang: LangSpec, line: string, sinkKind: string): string[] {
  const hints: string[] = [];
  for (const rule of byLanguage(sanitizerByLang, SANITIZERS, lang.id)) {
    if (rule.kind !== "*" && rule.kind !== sinkKind) continue;
    if (rule.exceptKinds?.includes(sinkKind)) continue;
    if (rule.re.test(line)) hints.push(rule.note);
  }
  return hints;
}
