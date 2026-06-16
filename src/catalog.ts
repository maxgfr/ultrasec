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
    callees: ["exec", "execSync", "spawn", "spawnSync", "system", "popen", "Popen", "shell_exec", "passthru", "proc_open", "check_output", "check_call", "call", "run"],
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
    callees: ["readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "sendFile", "unlink", "open", "readdir", "appendFile"],
    title: "Path traversal",
    note: "Tainted data used as a filesystem path. Verify it's confined (basename/realpath + allow-list under a base dir).",
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
  { kind: "http", languages: ["javascript"], re: /(?<![\w.])req(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies|url|originalUrl|hostname|ip)\b/, title: "HTTP request input" },
  { kind: "http", languages: ["javascript"], re: /\bctx\s*\.\s*(?:request|query|params|body)\b/, title: "Koa/HTTP context input" },
  { kind: "http", languages: ["python"], re: /(?<![\w.])request\s*\.\s*(?:args|form|values|json|data|files|cookies|headers|GET|POST)\b/, title: "HTTP request input" },
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
  { kind: "*", languages: ["*"], re: /\bparseInt\b|\bNumber\(|\bInteger\.parse|validator\.|\bz\.|Joi\.|\bisInt\b|\bUUID\b/, note: "type-coercion/validation present" },
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
