import { readText, walk } from "./walk.js";
import type { Finding, Severity } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";

// Authentication-token weaknesses — the JWT / OAuth / OIDC / SAML shapes that a
// taint walk can't reach because the flaw is a verification that DOESN'T happen,
// not data flowing to a sink.
//
// LINE / STATEMENT scan, zero-dependency, same contract as src/webconfig.ts:
// every finding is a CANDIDATE the auditor confirms, grounded on a resolvable
// [file:line]. A hardcoded secret here folds into gitleaks' finding via the
// cross-tool correlator (same location → one finding, both in `sources[]`).
// Category is `crypto` for algorithm/secret/hash weaknesses, `authz` for the
// flow/redirect/session ones; the CWE is what the coverage packs key on.

export interface AuthShape {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  category: "crypto" | "authz";
  note: string;
}

/** The shapes, kept as data so the reference and the engine cannot drift. */
export const AUTH_SHAPES: Record<string, AuthShape> = {
  "jwt-alg-none": {
    id: "jwt-alg-none",
    title: "JWT accepts the `none` algorithm",
    severity: "critical",
    cwe: "CWE-347",
    category: "crypto",
    note: "`alg: none` / `algorithms: ['none']` (or Go's `SigningMethodNone`) lets an attacker strip the signature and forge any token. Never allow it on the verify side.",
  },
  "jwt-no-verify-alg": {
    id: "jwt-no-verify-alg",
    title: "JWT verified without pinning the algorithm",
    severity: "high",
    cwe: "CWE-347",
    note: "`jwt.verify(token, key)` with no `algorithms` option accepts whatever the token's header claims — the RS256→HS256 key-confusion attack, where the RSA public key is used as an HMAC secret. Pin `algorithms` explicitly.",
    category: "crypto",
  },
  "jwt-decode": {
    id: "jwt-decode",
    title: "JWT decoded without verifying the signature",
    severity: "high",
    cwe: "CWE-347",
    category: "crypto",
    note: "`jwt.decode()` (vs. `verify`), or `verify_signature: False` / `verify=False`, reads the claims WITHOUT checking the signature — the token is attacker-authored. Only ever decode-without-verify a token you already verified.",
  },
  "jwt-expiry": {
    id: "jwt-expiry",
    title: "JWT expiration not enforced",
    severity: "medium",
    cwe: "CWE-613",
    category: "authz",
    note: "`ignoreExpiration: true` / `verify_exp: False` accepts a token forever — a stolen or leaked token never stops working. Enforce `exp`.",
  },
  "jwt-secret-hardcoded": {
    id: "jwt-secret-hardcoded",
    title: "JWT signed/verified with a hardcoded secret",
    severity: "high",
    cwe: "CWE-798",
    category: "crypto",
    note: "A string-literal HMAC secret in source is readable by anyone with the code and cannot be rotated without a deploy — with it an attacker mints valid tokens. Load it from config/secret storage.",
  },
  "jwt-weak-secret": {
    id: "jwt-weak-secret",
    title: "JWT signed/verified with a weak/default secret",
    severity: "high",
    cwe: "CWE-521",
    category: "crypto",
    note: "A guessable secret (`secret`, `changeme`, `password`…) is brute-forceable offline from a single captured token, after which an attacker forges any token. Use a long random secret from secret storage.",
  },
  "oauth-implicit": {
    id: "oauth-implicit",
    title: "OAuth implicit flow (response_type=token)",
    severity: "medium",
    cwe: "CWE-757",
    category: "authz",
    note: "The implicit flow returns the access token in the URL fragment — logged, cached, and leak-prone. Use the authorization-code flow with PKCE.",
  },
  "oauth-redirect-uri": {
    id: "oauth-redirect-uri",
    title: "Loose redirect_uri validation",
    severity: "high",
    cwe: "CWE-1385",
    category: "authz",
    note: "Validating redirect_uri with startsWith / prefix / substring lets `https://good.com.evil.com` (or `?next=`) pass and steals the code/token. Match the full registered URI exactly.",
  },
  "oauth-state-pkce": {
    id: "oauth-state-pkce",
    title: "Authorization-code request without state / PKCE",
    severity: "medium",
    cwe: "CWE-352",
    category: "authz",
    note: "An authorize request (`response_type=code`) with no `state` and no `code_challenge` is open to CSRF / code-injection on the callback. Send and verify `state`, and use PKCE.",
  },
  "saml-signature": {
    id: "saml-signature",
    title: "SAML signature validation disabled",
    severity: "critical",
    cwe: "CWE-347",
    category: "authz",
    note: "`wantAssertionsSigned: false` / `checkResponseSignature: false` / `validateSignature: false` accepts an unsigned (forgeable) assertion — full authentication bypass.",
  },
  "password-hash": {
    id: "password-hash",
    title: "Weak password hashing",
    severity: "high",
    cwe: "CWE-916",
    category: "crypto",
    note: "MD5/SHA-1 (or a bcrypt cost < 10) for passwords is brute-forceable at scale. Use bcrypt/scrypt/argon2 with a sound work factor.",
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

const WEAK_SECRETS = new Set([
  "secret",
  "secretkey",
  "secret_key",
  "changeme",
  "change-me",
  "password",
  "passwd",
  "pass",
  "test",
  "testing",
  "jwt",
  "jwtsecret",
  "key",
  "mysecret",
  "supersecret",
  "123456",
  "admin",
  "default",
]);

function hit(rel: string, line: number, shape: AuthShape, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: shape.category,
    ident: `authtokens:${shape.id}:${rel}:${line}`,
    title: `Auth token — ${shape.title}`,
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

// Per-line rules that need no cross-token context, language-gated.
const LINE_RULES: { langs: Set<string> | null; re: RegExp; shape: string }[] = [
  // alg: none across ecosystems.
  { langs: null, re: /alg(?:orithm)?s?\s*[:=]\s*\[?\s*['"]none['"]/i, shape: "jwt-alg-none" },
  { langs: null, re: /['"]alg['"]\s*=>\s*['"]none['"]/i, shape: "jwt-alg-none" },
  { langs: new Set(["go"]), re: /SigningMethodNone|UnsafeAllowNoneSignatureType/, shape: "jwt-alg-none" },
  // decode-without-verify.
  { langs: JS, re: /\bjwt\.decode\s*\(/, shape: "jwt-decode" },
  { langs: new Set(["py"]), re: /verify_signature['"]?\s*:\s*False|\bverify\s*=\s*False\b/, shape: "jwt-decode" },
  // expiry not enforced.
  { langs: JS, re: /ignoreExpiration\s*:\s*true/, shape: "jwt-expiry" },
  { langs: new Set(["py"]), re: /verify_exp['"]?\s*:\s*False/, shape: "jwt-expiry" },
  // implicit flow.
  { langs: null, re: /response_type\s*[=:]\s*['"]?token\b/i, shape: "oauth-implicit" },
  // SAML signature off.
  {
    langs: null,
    re: /want(?:Assertions|Message)Signed\s*[:=]\s*false|checkResponseSignature\s*[:=]\s*false|validateSignature\s*[:=]\s*false|want(?:Assertions|Message)Signed["']?\s*=>\s*false/i,
    shape: "saml-signature",
  },
  // loose redirect_uri validation.
  { langs: null, re: /(?:redirect_uri|redirecturi|redirect_url|redirecturl)[^\n]*\.(?:startsWith|indexOf|includes|search)\s*\(/i, shape: "oauth-redirect-uri" },
];

// Weak password hashing — the call and a password-ish operand on the same line.
const PWHASH_RULES: { langs: Set<string>; re: RegExp }[] = [
  { langs: JS, re: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)[^\n]*(?:pass|pwd)/i },
  { langs: new Set(["py"]), re: /hashlib\.(?:md5|sha1)\(\s*[^)]*(?:pass|pwd)/i },
  { langs: new Set(["php"]), re: /\b(?:md5|sha1)\(\s*\$?(?:pass|pwd)/i },
];

function scanJwtCalls(rel: string, content: string, ext: string, out: Finding[]): void {
  if (!JS.has(ext) && ext !== "py" && ext !== "php") return;
  // A string-literal secret in a sign/verify/encode/decode call: hardcoded, and
  // weak/default if it's a guessable word.
  const secretRe = /(?:jwt\.(?:sign|verify|encode|decode)|JWT::(?:encode|decode))\s*\(\s*[^,]+,\s*(['"])([^'"]{1,64})\1/g;
  for (const m of content.matchAll(secretRe)) {
    const ln = lineOf(content, m.index ?? 0);
    const literal = (m[2] ?? "").trim().toLowerCase();
    const shape = WEAK_SECRETS.has(literal) ? "jwt-weak-secret" : "jwt-secret-hardcoded";
    out.push(hit(rel, ln, AUTH_SHAPES[shape]!, m[0]));
  }
  // jwt.verify(...) that never pins `algorithms` — the key-confusion enabler.
  if (JS.has(ext)) {
    for (const m of content.matchAll(/\bjwt\.verify\s*\(/g)) {
      const open = (m.index ?? 0) + m[0].length - 1;
      const args = balanced(content, open);
      if (args === null) continue;
      if (!/algorithms/.test(args)) out.push(hit(rel, lineOf(content, m.index ?? 0), AUTH_SHAPES["jwt-no-verify-alg"]!, m[0]));
    }
  }
}

// Authorization-code requests missing BOTH state and PKCE — a per-file heuristic
// (low confidence): the shape only makes sense across the whole request builder.
function scanOAuthStatePkce(rel: string, content: string, out: Finding[]): void {
  const m = /response_type\s*[=:]\s*['"]?code\b/i.exec(content);
  if (!m) return;
  const hasState = /[?&]state=|['"]state['"]\s*[:=]/.test(content);
  const hasPkce = /code_challenge/i.test(content);
  if (hasState && hasPkce) return;
  const f = hit(rel, lineOf(content, m.index ?? 0), AUTH_SHAPES["oauth-state-pkce"]!, m[0]);
  f.confidence = "low";
  out.push(f);
}

/** Audit a repo for authentication-token weaknesses. Returns candidates. */
export function auditAuthTokens(repo: string, prune?: (rel: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const wf of walk(repo)) {
    if (prune?.(wf.rel)) continue;
    const ext = extOf(wf.rel);
    if (!CODE.has(ext)) continue;
    const content = readText(wf.abs);
    if (!content) continue;
    const rel = wf.rel;

    for (const l of lines(content)) {
      for (const r of LINE_RULES) if ((r.langs === null || r.langs.has(ext)) && r.re.test(l.text)) out.push(hit(rel, l.n, AUTH_SHAPES[r.shape]!, l.text));
      for (const r of PWHASH_RULES) if (r.langs.has(ext) && r.re.test(l.text)) out.push(hit(rel, l.n, AUTH_SHAPES["password-hash"]!, l.text));
      // bcrypt work factor below 10.
      const cost = /(?:genSalt(?:Sync)?|bcrypt\.hash(?:Sync)?)\s*\([^)]*?(?:^|,)\s*(\d{1,2})\s*[,)]/.exec(l.text);
      if (cost && Number(cost[1]) < 10) out.push(hit(rel, l.n, AUTH_SHAPES["password-hash"]!, l.text));
    }

    scanJwtCalls(rel, content, ext, out);
    scanOAuthStatePkce(rel, content, out);
  }
  return out;
}
