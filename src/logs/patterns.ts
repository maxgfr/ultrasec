import type { Severity } from "../types.js";

// The deterministic attack-signature catalog for `ultrasec logs` — the analogue
// of `src/catalog.ts` for the taint engine. Data-only + matchers; recall over
// precision is the taint catalog's stance, but log signatures are noisier by
// nature (every hit is one attacker-controlled HTTP request/UA/line, not a
// reviewed code path) so these regexes stay deliberately CONSERVATIVE —
// precision over recall. A hit is a candidate for the AI to triage, never a
// verdict (see the log-forensics playbook).

export type SignatureFamily = "sqli" | "xss" | "traversal" | "cmdinj" | "probe-path";

export interface AttackSignature {
  /** Stable id — part of the finding's content-hash, so keep it constant once shipped. */
  id: string;
  family: SignatureFamily;
  /** Baseline severity, before the 2xx-escalation rule (see ESCALATION_FAMILIES). */
  severity: Severity;
  re: RegExp;
  title: string;
  note: string;
}

// Hoisted so `analyze.ts`'s recon→hit behavioral detector can reuse the exact
// same regex object the probe-path signature uses below — one source of truth
// for "what counts as a sensitive path", never a second near-identical copy
// that could drift.
export const PROBE_PATH_RE =
  /(^|\/)(\.env|\.git\/config|wp-login\.php|xmlrpc\.php|phpmyadmin|\.aws\/credentials|actuator\/[\w-]*|server-status|\.ssh\/|vendor\/phpunit|id_rsa)([/?"]|$)/i;

export const ATTACK_SIGNATURES: AttackSignature[] = [
  // ── sqli ──────────────────────────────────────────────────────────────────
  {
    id: "sqli-union-select",
    family: "sqli",
    severity: "high",
    re: /\bunion\b[\s\S]{0,40}\bselect\b/i,
    title: "SQL injection — UNION SELECT",
    note: "A UNION SELECT within 40 chars is the classic column-count-probing / data-exfiltration SQLi shape.",
  },
  {
    id: "sqli-boolean-tautology",
    family: "sqli",
    severity: "high",
    re: /'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+/i,
    title: "SQL injection — boolean tautology",
    note: "A `' OR 1=1`-style tautology used to bypass a WHERE clause.",
  },
  {
    id: "sqli-time-based",
    family: "sqli",
    severity: "high",
    re: /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
    title: "SQL injection — time-based blind probe",
    note: "A sleep/benchmark/waitfor call used to infer data via response timing when output isn't reflected.",
  },
  {
    id: "sqli-schema-probe",
    family: "sqli",
    severity: "medium",
    re: /\b(information_schema|@@version|xp_cmdshell)\b/i,
    title: "SQL injection — schema/engine probe",
    note: "A reference to information_schema/@@version/xp_cmdshell — fingerprinting the DB engine or reaching for RCE.",
  },
  // ── xss ───────────────────────────────────────────────────────────────────
  {
    id: "xss-script-probe",
    family: "xss",
    severity: "medium",
    re: /<script\b|onerror\s*=|javascript:/i,
    title: "Cross-site scripting probe",
    note: "A <script>/onerror=/javascript: payload attempted in a request value.",
  },
  // ── traversal ─────────────────────────────────────────────────────────────
  {
    id: "traversal-dotdot",
    family: "traversal",
    severity: "medium",
    re: /(\.\.\/|\.\.\\){2,}/,
    title: "Path traversal — ../ sequence",
    note: "Two or more ../ (or ..\\) segments — an attempt to escape the served directory.",
  },
  {
    id: "traversal-sensitive-file",
    family: "traversal",
    severity: "high",
    re: /\/etc\/passwd|\/proc\/self\/environ|boot\.ini|win\.ini/i,
    title: "Path traversal — sensitive file target",
    note: "The request names a classic traversal target (/etc/passwd, /proc/self/environ, boot.ini, win.ini).",
  },
  // ── cmdinj ────────────────────────────────────────────────────────────────
  {
    id: "cmdinj-shell-chain",
    family: "cmdinj",
    severity: "high",
    re: /(;|\||\$\(|`|&&)\s*(wget|curl|nc|bash|sh|python|powershell)\b/i,
    title: "OS command injection probe",
    note: "A shell metacharacter (;|$(`&&) immediately followed by a downloader/shell/interpreter — a command-chaining attempt.",
  },
  // ── probe-path ────────────────────────────────────────────────────────────
  {
    id: "probe-sensitive-path",
    family: "probe-path",
    severity: "low",
    // `actuator\/[\w-]*` (not bare `actuator\/`): a Spring Boot actuator probe
    // always names an endpoint segment (`/actuator/env`, `/actuator/health`,
    // `/actuator/heapdump`, `/actuator/beans`, …) — a bare `actuator\/` alt only
    // matched `/actuator/` itself, missing every real recon hit. `[\w-]*` (zero
    // or more, so the bare `/actuator/` case still matches too) consumes the
    // endpoint name; the trailing `([/?"]|$)` boundary then only has to clear
    // the char AFTER the endpoint (a further `/` for a nested path like
    // `/actuator/health/liveness`, `?`, `"`, or end-of-string) — same boundary
    // discipline as the rest of this alternation. It still requires a literal
    // `/` right after "actuator", so `/blog/actuator-tips` (hyphen, no slash)
    // does not match — see the benign-twin fixture line + test.
    re: PROBE_PATH_RE,
    title: "Sensitive-path probe",
    note: "A request for a well-known sensitive/config path (.env, .git/config, wp-login.php, cloud credentials, actuator…).",
  },
];

/** Known scanner/attack-tool user-agents. One finding per (file, name) — see analyze.ts. */
export const SCANNER_UAS: { name: string; re: RegExp }[] = [
  { name: "sqlmap", re: /sqlmap/i },
  { name: "nikto", re: /nikto/i },
  { name: "nuclei", re: /nuclei/i },
  { name: "masscan", re: /masscan/i },
  { name: "zgrab", re: /zgrab/i },
  { name: "acunetix", re: /acunetix/i },
  { name: "nmap", re: /nmap/i },
  { name: "dirbuster", re: /dirbuster/i },
  { name: "gobuster", re: /gobuster/i },
  { name: "wpscan", re: /wpscan/i },
  { name: "feroxbuster", re: /feroxbuster/i },
  { name: "wfuzz", re: /wfuzz/i },
  { name: "hydra", re: /hydra/i },
];

/**
 * Escalation rule (implemented in `analyze.ts`): a signature hit in one of
 * these families whose event status is 2xx escalates severity one notch
 * (low→medium, medium→high) with "(succeeded — 2xx)" appended to the message —
 * a probe that SUCCEEDED is materially worse than one that 404'd.
 */
export const ESCALATION_FAMILIES: readonly SignatureFamily[] = ["probe-path", "traversal"];

/** CWE per family, where obvious. `undefined` = no CWE attached (probe-path / scanner-ua). */
export const FAMILY_CWE: Record<SignatureFamily, string | undefined> = {
  sqli: "CWE-89",
  xss: "CWE-79",
  traversal: "CWE-22",
  cmdinj: "CWE-78",
  "probe-path": undefined,
};

// ── auth events (behavioral aggregation input) ───────────────────────────────
// One line's auth outcome, when it has one. Feeds the brute-force/credential-
// compromise detectors in `analyze.ts` — this module stays data-only (the
// window/state machinery lives with the rest of the behavioral aggregator).
export type AuthEventKind = "auth-fail" | "auth-success";

export interface AuthEventSignature {
  kind: AuthEventKind;
  re: RegExp;
}

// Conservative on purpose (same "precision over recall" stance as
// ATTACK_SIGNATURES above): literal sshd/PAM phrasing first, then a narrow
// generic-app fallback — never bare "failed"/"succeeded", which would fire on
// unrelated application errors.
export const AUTH_EVENTS: AuthEventSignature[] = [
  // sshd: "Failed password for [invalid user] X from IP port P ssh2",
  // "pam_unix(sshd:auth): authentication failure; ...", or a standalone
  // "Invalid user X from IP port P" line (sshd logs this before the
  // corresponding "Failed password" line for a not-a-real-account attempt).
  { kind: "auth-fail", re: /\b(Failed password|authentication failure|Invalid user)\b/i },
  // sshd: "Accepted password for X from IP port P ssh2" / "Accepted publickey ...".
  { kind: "auth-success", re: /\bAccepted (password|publickey)\b/i },
  // Generic application login phrasing — literal, not just "failed"/"succeeded".
  { kind: "auth-fail", re: /\b(login failed|authentication failed)\b/i },
  { kind: "auth-success", re: /\blogin succeeded\b/i },
];

/** First AUTH_EVENTS pattern that matches `text`, or `undefined` for a line
 *  with no recognizable auth outcome. A line matches at most one kind in
 *  practice (the sshd/generic phrasings are mutually exclusive), so "first
 *  match wins" never has to arbitrate a real conflict. */
export function classifyAuthEvent(text: string): AuthEventKind | undefined {
  for (const ev of AUTH_EVENTS) if (ev.re.test(text)) return ev.kind;
  return undefined;
}
