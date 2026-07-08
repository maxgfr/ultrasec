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
  title: string;
  note: string;
}

export const SINKS: SinkRule[] = [
  {
    kind: "sql",
    cwe: "CWE-89",
    severity: "high",
    languages: ["javascript", "python", "go", "java", "php", "ruby", "rust", "csharp", "kotlin", "scala"],
    callees: ["query", "execute", "executeQuery", "executemany", "raw", "queryRaw", "unsafe", "exec_query"],
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
    ],
    receivers: ["child_process", "subprocess", "os", "Runtime", "shell"],
    title: "OS command injection",
    note: "Tainted data in a shell command. Prefer argv-array exec (execFile/execve) over a shell string; verify no shell metacharacters reach a shell.",
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
    receivers: ["ldap", "ldapClient", "ldapjs", "client", "conn", "connection", "ld"],
    title: "LDAP injection",
    note: "Tainted data concatenated into an LDAP filter/DN. Escape with the LDAP escaping API (ldap.escape / escapeFilter / escapeDN).",
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

export function findSinks(lang: LangSpec, calls: Call[]): SinkHit[] {
  const out: SinkHit[] = [];
  for (const c of calls) {
    for (const rule of SINKS) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.callees.includes(c.callee)) continue;
      // Verb-shaped callees (get/post/…) are only a sink as a MEMBER call
      // (`axios.get`) — a bare `get(x)` is a generic getter, so skip it.
      if (rule.requireReceiver && !c.receiver) continue;
      // If the rule pins receivers and this call has a *different* known one, skip
      // it (cuts false positives like `arr.call(...)` matching the command rule).
      // Rules with no `receivers` (e.g. sql) match any receiver.
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
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
  { kind: "http", languages: ["java", "kotlin", "scala"], re: /\.get(?:Parameter|Header|QueryString)\s*\(/, title: "Servlet request input" },
  { kind: "http", languages: ["ruby"], re: /(?<![\w.])params\s*\[/, title: "Rails params input" },
  { kind: "http", languages: ["go"], re: /\br\s*\.\s*(?:URL|FormValue|PostFormValue|Header)\b/, title: "net/http request input" },
  { kind: "cli", languages: ["javascript"], re: /\bprocess\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["python"], re: /\bsys\.argv\b/, title: "CLI argument" },
  { kind: "cli", languages: ["go"], re: /\bos\.Args\b/, title: "CLI argument" },
  { kind: "env", languages: ["javascript"], re: /\bprocess\.env\b/, title: "Environment variable" },
  { kind: "env", languages: ["python"], re: /\bos\.(?:environ|getenv)\b/, title: "Environment variable" },
  { kind: "env", languages: ["*"], re: /\bgetenv\s*\(/, title: "Environment variable" },
  { kind: "stdin", languages: ["python"], re: /\binput\s*\(/, title: "Interactive/stdin input" },
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
