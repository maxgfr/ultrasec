import { readText, walk, type RepoTree } from "./walk.js";
import type { Finding, Severity } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";

// API / web misconfiguration — the config shapes a taint walk can't see because
// they have no source and no sink, only a value that is wrong on its own line.
//
// Like `src/actions.ts` this is a LINE / STATEMENT scan, not a full parse: no
// dependency may enter the zero-dep bundle. Every finding is a CANDIDATE the
// auditor confirms against the deployment (a wildcard CORS on an internal-only
// service is a different risk from the same on a public API), and every finding
// is grounded on a resolvable [file:line] so the `check` gate holds. Category is
// always `config`; the CWE is what the coverage packs (Top 10 / API Top 10 /
// CWE Top 25) key on — see src/coverage.ts.

export interface WebConfigShape {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  note: string;
}

/** The shapes, kept as data so the reference doc and the engine cannot drift. */
export const WEBCONFIG_SHAPES: Record<string, WebConfigShape> = {
  "cors-reflect": {
    id: "cors-reflect",
    title: "CORS reflects the request Origin",
    severity: "high",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin echoes the caller's Origin (or `origin: true`). Any site can read authenticated responses cross-origin — reflection is a wildcard that also passes the credentialed-request check.",
  },
  "cors-wildcard-credentials": {
    id: "cors-wildcard-credentials",
    title: "Wildcard CORS with credentials",
    severity: "high",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin `*` together with Allow-Credentials `true`. Browsers block this combination, so shipping it means either it is ineffective or an origin is reflected elsewhere — check which.",
  },
  "cors-wildcard": {
    id: "cors-wildcard",
    title: "Wildcard CORS origin",
    severity: "medium",
    cwe: "CWE-942",
    note: "Access-Control-Allow-Origin `*` exposes responses to every origin. Safe only if the endpoint returns nothing per-user and carries no credentials.",
  },
  "cookie-httponly": {
    id: "cookie-httponly",
    title: "Cookie set without HttpOnly",
    severity: "medium",
    cwe: "CWE-1004",
    note: "A session/auth cookie readable from JavaScript is stealable by any XSS. Set HttpOnly unless the client genuinely must read it.",
  },
  "cookie-secure": {
    id: "cookie-secure",
    title: "Cookie set without Secure",
    severity: "medium",
    cwe: "CWE-614",
    note: "Without Secure the cookie is sent over plain HTTP and can be captured on the wire. Set Secure for anything session-bearing.",
  },
  "cookie-samesite": {
    id: "cookie-samesite",
    title: "Cookie set without SameSite",
    severity: "low",
    cwe: "CWE-1275",
    note: "No SameSite leaves the cookie attached to cross-site requests — the CSRF precondition. Set SameSite=Lax or Strict.",
  },
  "cookie-samesite-none-insecure": {
    id: "cookie-samesite-none-insecure",
    title: "SameSite=None cookie without Secure",
    severity: "high",
    cwe: "CWE-1275",
    note: "SameSite=None opts the cookie INTO cross-site sending; without Secure it also travels over plain HTTP. Browsers reject this pair, so it is both a CSRF and a transport exposure.",
  },
  "tls-verify": {
    id: "tls-verify",
    title: "TLS certificate verification disabled",
    severity: "high",
    cwe: "CWE-295",
    note: "Certificate/hostname verification turned off makes every outbound TLS call trivially machine-in-the-middle-able. This is almost never right outside a test.",
  },
  debug: {
    id: "debug",
    title: "Debug / verbose-error mode enabled",
    severity: "medium",
    cwe: "CWE-489",
    note: "Framework debug mode leaks stack traces, config and (Flask/Werkzeug, Rails) an interactive console or source. It must be off in production.",
  },
  "header-csp": {
    id: "header-csp",
    title: "Content-Security-Policy weakened",
    severity: "medium",
    cwe: "CWE-693",
    note: "`unsafe-inline` / `unsafe-eval` / a `*` source in the CSP re-opens the XSS class the header exists to close.",
  },
  "header-xfo": {
    id: "header-xfo",
    title: "X-Frame-Options allows framing",
    severity: "medium",
    cwe: "CWE-1021",
    note: "`ALLOWALL` (or the deprecated `ALLOW-FROM`) leaves the page framable — the clickjacking precondition. Use DENY/SAMEORIGIN or a CSP frame-ancestors.",
  },
  "header-hsts": {
    id: "header-hsts",
    title: "HSTS disabled (max-age=0)",
    severity: "medium",
    cwe: "CWE-319",
    note: "`max-age=0` turns Strict-Transport-Security off, so a first/again request can be downgraded to HTTP.",
  },
  "header-referrer": {
    id: "header-referrer",
    title: "Referrer-Policy leaks full URL",
    severity: "low",
    cwe: "CWE-200",
    note: "`unsafe-url` sends the full referring URL (path + query, possibly a token) cross-origin.",
  },
  "dir-listing": {
    id: "dir-listing",
    title: "Directory listing enabled",
    severity: "medium",
    cwe: "CWE-548",
    note: "Autoindex / serve-index exposes the file tree, turning any forgotten file into a disclosure.",
  },
  "csrf-disabled": {
    id: "csrf-disabled",
    title: "CSRF protection disabled",
    severity: "high",
    cwe: "CWE-352",
    note: "The framework's CSRF guard is switched off (commented out, skipped, or exempted). Any state-changing route it covered can now be driven from an attacker's page using the victim's cookies.",
  },
  "graphql-introspection": {
    id: "graphql-introspection",
    title: "GraphQL introspection / dev UI enabled",
    severity: "medium",
    cwe: "CWE-200",
    note: "Introspection (or GraphiQL/Playground) hands an attacker the whole schema. Disable it in production.",
  },
};

interface Line {
  n: number;
  text: string;
}

function lines(content: string): Line[] {
  return content.split(/\r?\n/).map((text, i) => ({ n: i + 1, text }));
}

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i === -1 ? "" : rel.slice(i + 1).toLowerCase();
}

const JS = new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"]);
const CODE = new Set([...JS, "py", "go", "java", "kt", "scala", "php", "rb", "cs"]);
// Files whose CONTENT we scan: code plus the web-server/config formats where
// these values are just as often set.
const SCAN = new Set([...CODE, "conf", "nginx", "yaml", "yml"]);

function hit(rel: string, line: number, shape: WebConfigShape, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: "config",
    ident: `webconfig:${shape.id}:${rel}:${line}`,
    title: `Web misconfig — ${shape.title}`,
    severity: shape.severity,
    message: `${shape.note}\n\nEvidence: \`${evidence.trim().slice(0, 160)}\``,
    file: rel,
    line,
    cwe: shape.cwe,
  });
}

/** Extract the balanced `(...)` argument text starting at the `(` at `open`. */
function balanced(hay: string, open: number): string | null {
  let depth = 0;
  for (let i = open; i < hay.length; i++) {
    const c = hay[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return hay.slice(open + 1, i);
    }
  }
  return null;
}

function lineOf(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === "\n") n++;
  return n;
}

// ── TLS certificate verification disabled (CWE-295) ─────────────────────────
// Language-gated so a Python `verify=False` never lints a Go file, and vice versa.
const TLS_RULES: { langs: Set<string>; re: RegExp }[] = [
  { langs: JS, re: /rejectUnauthorized\s*:\s*false/ },
  { langs: new Set(["py"]), re: /\bverify\s*=\s*False\b/ },
  { langs: new Set(["py"]), re: /_create_unverified_context|ssl\.\s*CERT_NONE/ },
  { langs: new Set(["go"]), re: /InsecureSkipVerify\s*:\s*true/ },
  { langs: new Set(["php"]), re: /CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:0|false)\b/i },
  { langs: new Set(["java", "kt", "scala"]), re: /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustAllCerts|trustAllCerts/ },
];

// ── CSRF guard disabled (CWE-352) ───────────────────────────────────────────
// Measured on railsgoat, whose `#protect_from_forgery with: :exception` is the
// single line that opens every state-changing route in the app.
const CSRF_RULES: { langs: Set<string>; re: RegExp }[] = [
  { langs: new Set(["rb"]), re: /^\s*#\s*protect_from_forgery\b/ },
  { langs: new Set(["rb"]), re: /\bskip_before_action\s+:verify_authenticity_token\b/ },
  { langs: new Set(["rb"]), re: /\bprotect_from_forgery\s+with:\s*:null_session\b/ },
  { langs: new Set(["py"]), re: /^\s*@csrf_exempt\b/ },
  { langs: new Set(["py"]), re: /^\s*#\s*['"]django\.middleware\.csrf\.CsrfViewMiddleware['"]/ },
  { langs: JS, re: /\bcsrf(?:Prevention)?\s*:\s*false\b/ },
  { langs: new Set(["php"]), re: /['"]csrf(?:_protection)?['"]\s*=>\s*false/i },
];

// ── Framework debug mode (CWE-489) ──────────────────────────────────────────
const DEBUG_RULES: { langs: Set<string>; re: RegExp }[] = [
  { langs: new Set(["py"]), re: /\.run\([^)]*\bdebug\s*=\s*True/ },
  { langs: new Set(["py"]), re: /^\s*DEBUG\s*=\s*True\b/ },
  { langs: new Set(["rb"]), re: /consider_all_requests_local\s*=\s*true/ },
  { langs: new Set(["php"]), re: /['"]debug['"]\s*=>\s*true/ },
];

function scanCors(rel: string, content: string, out: Finding[]): void {
  // Origin-setting sites and whether credentials are enabled anywhere in the file.
  const credentials = /Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?\s*true/i.test(content) || /\bcredentials\s*:\s*true/.test(content);
  const reflectRe = /Access-Control-Allow-Origin['"]?\s*[:,]\s*[^,\n)]*\b(?:req|request|ctx|headers?)\b[^,\n)]*origin|(?:^|[^\w.])origin\s*:\s*true\b/gi;
  const wildcardRe = /Access-Control-Allow-Origin\s*:\s*\*|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]|(?:^|[^\w.])origin\s*:\s*['"]\*['"]/gi;

  const seen = new Set<number>();
  for (const m of content.matchAll(reflectRe)) {
    const ln = lineOf(content, m.index ?? 0);
    seen.add(ln);
    out.push(hit(rel, ln, WEBCONFIG_SHAPES["cors-reflect"]!, m[0]));
  }
  for (const m of content.matchAll(wildcardRe)) {
    const ln = lineOf(content, m.index ?? 0);
    if (seen.has(ln)) continue; // a reflect on this line already covers it
    out.push(hit(rel, ln, WEBCONFIG_SHAPES[credentials ? "cors-wildcard-credentials" : "cors-wildcard"]!, m[0]));
  }
}

// Cookie-setting calls whose flags we can read on the (possibly multi-line)
// statement. Java `new Cookie(...)` stays with the catalog `cookie` sink.
const COOKIE_CALL = /\b(?:res(?:ponse)?\.cookie|reply\.setCookie|ctx\.cookies\.set|cookies\.set|setcookie)\s*\(/gi;

function scanCookies(rel: string, content: string, out: Finding[]): void {
  for (const m of content.matchAll(COOKIE_CALL)) {
    if (/clearCookie/i.test(m[0])) continue;
    const open = (m.index ?? 0) + m[0].length - 1; // index of '('
    const args = balanced(content, open);
    if (args === null) continue;
    const ln = lineOf(content, m.index ?? 0);
    const hasOptions = /\{/.test(args) || /setcookie/i.test(m[0]);
    if (!hasOptions) {
      // res.cookie('n','v') with no options object — the two flags that matter most.
      out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-httponly"]!, `${m[0]}…`));
      out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-secure"]!, `${m[0]}…`));
      continue;
    }
    const hasHttpOnly = /httponly\s*[:=]?\s*(?:true|1)/i.test(args) || /['"]httponly['"]\s*=>\s*true/i.test(args);
    const hasSecure = /\bsecure\s*[:=]?\s*(?:true|1)/i.test(args) || /['"]secure['"]\s*=>\s*true/i.test(args);
    const sameSite = /samesite\s*[:=]?\s*['"]?(strict|lax|none)/i.exec(args) || /['"]samesite['"]\s*=>\s*['"]?(strict|lax|none)/i.exec(args);
    if (!hasHttpOnly) out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-httponly"]!, m[0]));
    if (!hasSecure) out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-secure"]!, m[0]));
    if (!sameSite) out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-samesite"]!, m[0]));
    else if (sameSite[1]?.toLowerCase() === "none" && !hasSecure) out.push(hit(rel, ln, WEBCONFIG_SHAPES["cookie-samesite-none-insecure"]!, m[0]));
  }
}

/**
 * Audit a repo for API / web misconfiguration. Returns candidates — a wildcard
 * CORS on an internal service is a different risk from the same on a public API,
 * and only the auditor knows which this is.
 */
export function auditWebConfig(repo: string, prune?: (rel: string) => boolean, tree?: RepoTree): Finding[] {
  const out: Finding[] = [];
  const read = tree?.read ?? readText;
  for (const wf of tree?.files ?? walk(repo)) {
    if (prune?.(wf.rel)) continue;
    const ext = extOf(wf.rel);
    if (!SCAN.has(ext)) continue;
    const content = read(wf.abs);
    if (!content) continue;
    const rel = wf.rel;
    const ls = lines(content);

    for (const l of ls) {
      for (const r of TLS_RULES) if (r.langs.has(ext) && r.re.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["tls-verify"]!, l.text));
      // NODE_TLS_REJECT_UNAUTHORIZED=0 is dangerous in any file (code, shell, yaml).
      if (/NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0\b/.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["tls-verify"]!, l.text));
      for (const r of DEBUG_RULES) if (r.langs.has(ext) && r.re.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES.debug!, l.text));

      if (/Content-Security-Policy/i.test(l.text) && /unsafe-inline|unsafe-eval|(?:default|script|object)-src[^;'"]*\*/i.test(l.text))
        out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-csp"]!, l.text));
      if (/X-Frame-Options['"]?\s*[:,]\s*['"]?\s*(?:ALLOWALL|ALLOW-FROM)/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-xfo"]!, l.text));
      if (/Strict-Transport-Security[^\n]*max-age\s*=\s*0\b/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-hsts"]!, l.text));
      if (/Referrer-Policy['"]?\s*[:,]\s*['"]?\s*unsafe-url/i.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["header-referrer"]!, l.text));

      if (/^\s*autoindex\s+on\b/i.test(l.text) || /\bserve-index\s*\(/.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["dir-listing"]!, l.text));
      if (/\b(?:introspection|graphiql|playground)\s*:\s*true\b/.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["graphql-introspection"]!, l.text));

      // CSRF guard switched off. Only shapes that HAVE a line to cite: a
      // commented-out guard, an explicit skip/exempt, or a `false` setting.
      // (A framework that never had one at all is an absence — that's the
      // access-control lens's job, not a groundable finding.)
      for (const r of CSRF_RULES) if (r.langs.has(ext) && r.re.test(l.text)) out.push(hit(rel, l.n, WEBCONFIG_SHAPES["csrf-disabled"]!, l.text));
    }

    scanCors(rel, content, out);
    scanCookies(rel, content, out);
  }
  return out;
}
