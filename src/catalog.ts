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
  title: string;
  note: string;
}

export const SINKS: SinkRule[] = [
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
    ],
    title: "SQL injection",
    note: "Tainted data concatenated into a SQL statement. Verify it isn't a parameterized/prepared query.",
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
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["*"],
    callees: ["eval", "Function", "runInThisContext", "runInContext", "compile", "execfile"],
    title: "Code injection / eval",
    note: "Tainted data evaluated as code. Almost never safe; verify the argument is a constant.",
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
    ],
    title: "Path traversal / archive extraction (zip-slip)",
    note: "Tainted data used as a filesystem path, or an archive extracted without validating entry names (zip-slip). Confine to a base dir (basename/realpath + allow-list) and reject entries that escape it.",
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
    kind: "xss",
    cwe: "CWE-79",
    severity: "medium",
    languages: ["javascript", "python", "php", "ruby"],
    callees: ["send", "write", "end", "html", "render_template_string", "writeHead"],
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
    callees: ["parseString", "parseXml", "parseFromString", "fromstring", "SAXParser", "DocumentBuilder", "XMLReader", "createDocument"],
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
    receivers: ["idc", "dirContext", "dctx", "ldapContext", "initialDirContext", "dirCtx"],
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
 */
export function findSinks(
  lang: LangSpec,
  calls: Call[],
  extraSinks?: SinkRule[],
  imports?: readonly { spec: string }[],
  localDefs?: ReadonlySet<string>,
): SinkHit[] {
  const byCallee = sinkIndex(extraSinks && extraSinks.length ? mergedSinks(extraSinks) : SINKS);
  const out: SinkHit[] = [];
  const specs = (imports ?? []).map((i) => i.spec.toLowerCase());
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
    for (const rule of rules) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      // Verb-shaped callees (get/post/…) are only a sink as a MEMBER call
      // (`axios.get`) — a bare `get(x)` is a generic getter, so skip it.
      if (rule.requireReceiver && !c.receiver) continue;
      // If the rule pins receivers and this call has a *different* known one, skip
      // it (cuts false positives like `arr.call(...)` matching the command rule).
      // Rules with no `receivers` (e.g. sql) match any receiver.
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
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
  { kind: "command", languages: ["*"], re: /\bexecFile\b|\bexecvp?\b|shlex\.quote|escapeshellarg/, note: "argv-array / quoting present" },
  { kind: "path", languages: ["*"], re: /\bbasename\b|\brealpath\b|secure_filename|path\.resolve|startsWith\(/, note: "path-confinement helper present" },
  // `escape(?:Html)?\b` could not match the camelCase family (`escapeAttrValue`),
  // and nothing looked for the `xss` library at all — so on a repo whose only
  // HTML sanitizer is `xssWrapper` wrapping `xss@1.0.15`, the brief that exists
  // to answer "which sanitizers does this project use?" named none of it.
  { kind: "xss", languages: ["*"], re: /\bescape[A-Z]?\w*\b|sanitize|DOMPurify|bleach|markupsafe|\bxss[A-Za-z]*\b/, note: "escaping/sanitizer present" },
  { kind: "deserialize", languages: ["*"], re: /safe_load|safeLoad|JSON\.parse/, note: "safe loader present" },
  { kind: "nosql", languages: ["*"], re: /mongo-?[sS]anitize|sanitizeFilter|\$eq\b/, note: "operator-stripping sanitizer present" },
  {
    kind: "xxe",
    languages: ["*"],
    re: /resolve_entities\s*=\s*False|feature_external_ges|FEATURE_SECURE_PROCESSING|noent\s*=\s*False|XMLConstants/,
    note: "external-entity resolution disabled",
  },
  { kind: "ldap", languages: ["*"], re: /ldap\.escape|escapeDN|escapeFilter|escape_filter_chars/, note: "LDAP escaping present" },
  { kind: "crlf", languages: ["*"], re: /encodeURIComponent|stripCRLF|replace\(\s*\/[^/]*[\\]r/, note: "CR/LF stripping present" },
  {
    kind: "proto",
    languages: ["*"],
    re: /__proto__|Object\.freeze|Object\.create\(\s*null|hasOwnProperty|structuredClone/,
    note: "prototype-pollution guard present",
  },
  { kind: "ssti", languages: ["*"], re: /autoescape|markupsafe|\|\s*e\b|escape\(/, note: "template autoescaping present" },
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
    re: /\bparseInt\b|\bNumber\(|\bInteger\.parse|validator\.|\bz\.|Joi\.|\bisInt\b|\bUUID\b/,
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
