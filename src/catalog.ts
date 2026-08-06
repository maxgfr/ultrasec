import type { Severity } from "./types.js";
import type { LangSpec, Call } from "./lang.js";

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
   *  substrings. For a technology-specific sink whose method name is generic
   *  (`client.search` is LDAP *or* Elasticsearch), the import is what
   *  disambiguates. Ignored when the file has no imports recorded, so the regex
   *  extraction tier — which may not see them — never loses the rule entirely. */
  requireModule?: string[];
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
  {
    kind: "command",
    cwe: "CWE-78",
    severity: "critical",
    languages: ["*"],
    callees: [
      "exec",
      "execSync",
      "spawn",
      "spawnSync",
      "system",
      "popen",
      "Popen",
      "shell_exec",
      "passthru",
      "proc_open",
      "check_output",
      "check_call",
      "call",
      "run",
      "ProcessBuilder",
      "getRuntime",
    ],
    receivers: ["child_process", "subprocess", "os", "Runtime", "shell", "getRuntime", "runtime"],
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
    kind: "code",
    cwe: "CWE-94",
    severity: "high",
    languages: ["*"],
    callees: ["eval", "Function", "runInThisContext", "runInContext", "compile", "execfile"],
    title: "Code injection / eval",
    note: "Tainted data evaluated as code. Almost never safe; verify the argument is a constant.",
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
    label: "URL attribute",
    title: "DOM XSS via a URL attribute",
    note: "Tainted data assigned to src/href executes when the scheme is `javascript:` or `data:`. Allow-list the scheme before assigning.",
  },
];

export function findTextSinks(lang: LangSpec, content: string): SinkHit[] {
  const out: SinkHit[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of TEXT_SINKS) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.re.test(line)) continue;
      out.push({ line: i + 1, callee: rule.label, kind: rule.kind, cwe: rule.cwe, severity: rule.severity, title: rule.title, note: rule.note });
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
}

/**
 * @param extraSinks Additional rules unioned in for this call ONLY (e.g.
 * `LOG_SINKS` under `scan --log-hygiene`). Omitted/empty ⇒ matches exactly
 * `SINKS`, byte-identical to before this param existed.
 */
export function findSinks(lang: LangSpec, calls: Call[], extraSinks?: SinkRule[], imports?: readonly { spec: string }[]): SinkHit[] {
  const rules = extraSinks && extraSinks.length ? [...SINKS, ...extraSinks] : SINKS;
  const out: SinkHit[] = [];
  const specs = (imports ?? []).map((i) => i.spec.toLowerCase());
  for (const c of calls) {
    for (const rule of rules) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.callees.includes(c.callee)) continue;
      // Verb-shaped callees (get/post/…) are only a sink as a MEMBER call
      // (`axios.get`) — a bare `get(x)` is a generic getter, so skip it.
      if (rule.requireReceiver && !c.receiver) continue;
      // If the rule pins receivers and this call has a *different* known one, skip
      // it (cuts false positives like `arr.call(...)` matching the command rule).
      // Rules with no `receivers` (e.g. sql) match any receiver.
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
      // Technology gate. Only enforced when imports were actually extracted:
      // an empty list means we couldn't see them, not that there are none.
      if (rule.requireModule && specs.length && !rule.requireModule.some((m) => specs.some((s) => s.includes(m)))) continue;
      out.push({
        line: c.line,
        callee: c.callee,
        receiver: c.receiver,
        kind: rule.kind,
        cwe: rule.cwe,
        severity: rule.severity,
        title: rule.title,
        note: rule.note,
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
    re: /(?<![\w.])req(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|url|originalUrl|hostname|ip|files|file)\b/,
    title: "HTTP request input",
  },
  { kind: "ws", languages: ["javascript"], re: /\.on\s*\(\s*['"](?:message|data)['"]/, title: "WebSocket/stream message" },
  { kind: "http", languages: ["javascript"], re: /\bctx\s*\.\s*(?:request|query|params|body)\b/, title: "Koa/HTTP context input" },
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

export function findSources(lang: LangSpec, content: string): SourceHit[] {
  const out: SourceHit[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of SOURCES) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      const m = rule.re.exec(line);
      if (m) out.push({ line: i + 1, kind: rule.kind, match: m[0], title: rule.title });
    }
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
}

export const SANITIZERS: SanitizerRule[] = [
  { kind: "sql", languages: ["*"], re: /\?|\$\d+|:\w+|%s|@\w+/, note: "looks parameterized (placeholder present)" },
  { kind: "command", languages: ["*"], re: /\bexecFile\b|\bexecvp?\b|shlex\.quote|escapeshellarg/, note: "argv-array / quoting present" },
  { kind: "path", languages: ["*"], re: /\bbasename\b|\brealpath\b|secure_filename|path\.resolve|startsWith\(/, note: "path-confinement helper present" },
  { kind: "xss", languages: ["*"], re: /\bescape(?:Html)?\b|sanitize|DOMPurify|bleach|markupsafe|escapeHTML/, note: "escaping/sanitizer present" },
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
  {
    kind: "reflect",
    languages: ["*"],
    re: /\bALLOWED\b|allowlist|allowList|\bin\s+\{|\bMap\s*\(|hasOwnProperty|\bdict\s*\[/,
    note: "allow-list lookup present",
  },
  { kind: "xpath", languages: ["*"], re: /setXPathVariable|XPathVariableResolver|\bbindVariable\b|\$\w+/, note: "XPath variable binding present" },
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
  },
];

/** Sanitizer hints found on a given line of code (for the candidate's note). */
export function findSanitizers(lang: LangSpec, line: string, sinkKind: string): string[] {
  const hints: string[] = [];
  for (const rule of SANITIZERS) {
    if (!appliesTo(rule.languages, lang.id)) continue;
    if (rule.kind !== "*" && rule.kind !== sinkKind) continue;
    if (rule.re.test(line)) hints.push(rule.note);
  }
  return hints;
}
