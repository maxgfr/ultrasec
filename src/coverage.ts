import type { Dossier } from "./store.js";
import type { Finding, Manifest } from "./types.js";

// The coverage matrix — the honest complement to "only report what you can
// exploit".
//
// A short report reads as "nothing there". It actually means "nothing there, in
// what I looked at". Those are very different statements to hand a maintainer,
// and nothing in the audit distinguishes them: a repo with no findings and a
// repo nobody checked produce the same SUMMARY.md.
//
// So every category is accounted for in exactly one bucket, and a category
// nothing touched is reported as UNEXAMINED rather than passed over. The
// engine can only see what it enumerated and what the findings cite; the
// judgment categories are marked for the auditor to answer explicitly, because
// "not applicable" without a reason is how coverage silently shrinks.
//
// The matrix is scored against a pluggable STANDARD (default OWASP ASVS). A
// standard is just an ordered list of categories, each naming the finding
// `kinds` (category, sink kind, or CWE id) whose presence proves the class was
// enumerated. Adding a standard adds a lens on the SAME findings — it never
// changes what was scanned.

export type CoverageState =
  /** The engine enumerates this class mechanically. */
  | "engine"
  /** A finding or discovery landed here — someone looked. */
  | "examined"
  /** Nothing in this audit touched it. NOT the same as "clean". */
  | "unexamined";

export interface AsvsCategory {
  id: string;
  title: string;
  /** Finding kinds whose presence proves the class was enumerated: a category
   *  (`authz`), a sink kind (`sql`), or a CWE id (`CWE-295`). */
  kinds?: string[];
  /** True when no deterministic signal can establish coverage — you must say. */
  judgment?: boolean;
  /** What answering it well requires. */
  hint: string;
  /** The opt-in `scan` pass this class needs in order to be enumerated at all.
   *  When the manifest records that the pass DID run, `hintWhenRan` replaces
   *  `hint` — telling a user to enable a flag they already passed is a confusing
   *  signal, and it is what made a run with 117 CWE-117 findings read as if the
   *  option had been forgotten. */
  requiresPass?: keyof NonNullable<Manifest["passes"]>;
  /** Advice for the case where `requiresPass` ran and still turned up nothing. */
  hintWhenRan?: string;
}

/** A named coverage standard: an ordered list of categories the report scores. */
export interface StandardPack {
  id: string;
  title: string;
  categories: AsvsCategory[];
}

/**
 * OWASP ASVS v4 chapters, trimmed to the ones a source audit can speak to.
 * Deliberately not the full 14: claiming coverage of "V10 Malicious Code" from a
 * taint walk would be exactly the coverage theatre this file exists to avoid.
 */
const ASVS_CATEGORIES: AsvsCategory[] = [
  {
    id: "V1",
    title: "Architecture & threat modelling",
    judgment: true,
    hint: "Did CONTEXT.md establish a trust model and a threat model, or was severity rated in the abstract?",
  },
  { id: "V2", title: "Authentication", judgment: true, hint: "Password/OTP/session-establishment paths read? Credential comparison constant-time?" },
  { id: "V3", title: "Session management", judgment: true, hint: "Token lifetime, rotation on privilege change, invalidation on logout." },
  {
    id: "V4",
    title: "Access control",
    kinds: ["authz"],
    judgment: true,
    hint: "The highest-yield class, and never enumerable: every route's guard vs. the object it returns (IDOR).",
  },
  {
    id: "V5",
    title: "Validation, sanitization & encoding",
    kinds: ["sql", "nosql", "command", "argv", "code", "path", "xss", "domxss", "ssti", "xxe", "ldap", "xpath", "crlf", "proto", "massassign", "csv"],
    hint: "Injection classes — the taint catalog's core.",
  },
  {
    id: "V6",
    title: "Stored cryptography",
    kinds: ["crypto"],
    judgment: true,
    hint: "Weak-hash detection is mechanical; key management, IV reuse and constant-time comparison are not.",
  },
  {
    id: "V7",
    title: "Error handling & logging",
    // Keyed on the CWEs, not on which pass produced them. `--log-hygiene` turns on
    // TWO passes with two different shapes: the line-content pass emits
    // `category: "logs"` + CWE-532, while the taint walk emits `category: "taint"`
    // + `sink.kind: "log"` + CWE-117. Listing only "logs" scored a run with 117
    // CWE-117 findings as "not examined" — the exact coverage theatre this file
    // exists to avoid, pointed the other way.
    kinds: ["logs", "log", "CWE-117", "CWE-532"],
    hint: "Needs `scan --log-hygiene` to be enumerated at all (CWE-117/532).",
    requiresPass: "logHygiene",
    hintWhenRan: "`--log-hygiene` ran and found no CWE-117/532 candidate — error handling and log content are still yours to read.",
  },
  {
    id: "V8",
    title: "Data protection & privacy",
    kinds: ["privacy"],
    judgment: true,
    hint: "Where personal data goes, how long it stays, whether pseudonymisation is reversible.",
  },
  { id: "V9", title: "Communications", judgment: true, hint: "TLS verification disabled anywhere? Certificate pinning claims that do not hold?" },
  { id: "V11", title: "Business logic", judgment: true, hint: "Workflow skipping, price/quantity tampering, replay, quota bypass, races on balance." },
  { id: "V12", title: "Files & resources", kinds: ["path"], hint: "Traversal and zip-slip are enumerated; upload type/size/AV policy is not." },
  {
    id: "V13",
    title: "API & web service",
    kinds: ["ssrf", "redirect"],
    judgment: true,
    hint: "SSRF and open redirect are enumerated; GraphQL field authz and mass-assignment on API models are not.",
  },
  {
    id: "V14",
    title: "Configuration & supply chain",
    kinds: ["dep", "secret", "config"],
    hint: "Dependencies, secrets, IaC, CI — including workflows that hand an agent the repo.",
  },
];

// OWASP Top 10 (2021). Each item names the finding kinds (category / sink kind /
// CWE) whose presence proves the class was looked at. Several stay `judgment`
// because the engine can only partially speak to them (authz, business logic).
const OWASP_TOP10_2021: AsvsCategory[] = [
  {
    id: "A01",
    title: "Broken access control",
    kinds: ["authz", "redirect", "CWE-352", "CWE-601", "CWE-1385"],
    judgment: true,
    hint: "Per-route guards vs. the object returned (IDOR/BOLA), CSRF, open redirect, path traversal on protected files.",
  },
  {
    id: "A02",
    title: "Cryptographic failures",
    kinds: ["crypto", "random", "CWE-295", "CWE-327", "CWE-328", "CWE-330", "CWE-614", "CWE-798", "CWE-521", "CWE-916"],
    judgment: true,
    hint: "Weak hashes/ciphers, TLS verification disabled, hardcoded/weak secrets, insecure randomness, cleartext transport.",
  },
  {
    id: "A03",
    title: "Injection",
    kinds: ["sql", "nosql", "command", "argv", "code", "ldap", "xpath", "ssti", "xxe", "xss", "domxss", "crlf", "csv"],
    hint: "The taint catalog's core — SQL/NoSQL/command/code/LDAP/XPath/template/XSS.",
  },
  {
    id: "A04",
    title: "Insecure design",
    judgment: true,
    hint: "Missing rate limiting, no threat model, business-logic abuse — read CONTEXT.md and the investigate leads.",
  },
  {
    id: "A05",
    title: "Security misconfiguration",
    kinds: ["config", "CWE-16", "CWE-200", "CWE-489", "CWE-942", "CWE-1004", "CWE-1275", "xxe"],
    hint: "CORS, security headers, cookie flags, debug/verbose errors, directory listing, GraphQL introspection, IaC.",
  },
  {
    id: "A06",
    title: "Vulnerable & outdated components",
    kinds: ["dep"],
    hint: "Dependency CVEs (Trivy/OSV/grype…) enumerated; EOL runtimes and unpatched frameworks are judgment.",
  },
  {
    id: "A07",
    title: "Identification & authentication failures",
    // CWE-916 (weak password hash) is mapped to A07 by OWASP, not only to A02 —
    // measured on DVWA, whose 17 md5-password findings otherwise left A07 reading
    // "not examined" while the audit had in fact looked straight at it.
    kinds: ["authz", "CWE-287", "CWE-347", "CWE-384", "CWE-521", "CWE-613", "CWE-798", "CWE-916"],
    judgment: true,
    hint: "JWT verification, session rotation/expiry, credential strength, brute-force protection.",
  },
  {
    id: "A08",
    title: "Software & data integrity failures",
    kinds: ["deserialize", "CWE-502", "config", "CWE-1427"],
    judgment: true,
    hint: "Insecure deserialization, unsigned updates, and CI/CD that hands an agent the repo (agentic-CI).",
  },
  {
    id: "A09",
    title: "Security logging & monitoring failures",
    // Same CWE-keyed union as ASVS V7 — see the note there.
    kinds: ["logs", "log", "CWE-117", "CWE-532"],
    judgment: true,
    hint: "Needs `scan --log-hygiene`; monitoring/alerting is out of a source audit's reach.",
    requiresPass: "logHygiene",
    hintWhenRan: "`--log-hygiene` ran and found nothing; monitoring/alerting is out of a source audit's reach either way.",
  },
  { id: "A10", title: "Server-side request forgery (SSRF)", kinds: ["ssrf"], hint: "SSRF sinks are enumerated by the taint walk." },
];

// OWASP API Security Top 10 (2023). Authorization items are irreducibly
// judgment — the engine can point at the routes, not decide the policy.
const OWASP_API_TOP10_2023: AsvsCategory[] = [
  {
    id: "API1",
    title: "Broken object level authorization (BOLA)",
    kinds: ["authz"],
    judgment: true,
    hint: "Every endpoint that takes an id: is the returned object scoped to the caller?",
  },
  {
    id: "API2",
    title: "Broken authentication",
    kinds: ["authz", "CWE-287", "CWE-347", "CWE-613", "CWE-521", "CWE-798"],
    judgment: true,
    hint: "JWT verification/alg/expiry, weak or hardcoded secrets, credential handling.",
  },
  {
    id: "API3",
    title: "Broken object property level authorization",
    kinds: ["massassign", "CWE-915"],
    judgment: true,
    hint: "Mass assignment onto privileged fields; over-disclosure of object properties.",
  },
  {
    id: "API4",
    title: "Unrestricted resource consumption",
    judgment: true,
    hint: "Rate limiting, pagination caps, GraphQL query cost/depth — not statically enumerable.",
  },
  {
    id: "API5",
    title: "Broken function level authorization (BFLA)",
    kinds: ["authz"],
    judgment: true,
    hint: "Admin/privileged functions reachable by a normal role; method or version downgrade.",
  },
  {
    id: "API6",
    title: "Unrestricted access to sensitive business flows",
    judgment: true,
    hint: "Automatable flows (checkout, signup) without abuse controls.",
  },
  { id: "API7", title: "Server-side request forgery", kinds: ["ssrf"], hint: "SSRF sinks (webhooks, imports, avatars) enumerated by the taint walk." },
  {
    id: "API8",
    title: "Security misconfiguration",
    kinds: ["config", "CWE-200", "CWE-489", "CWE-942", "CWE-1004", "CWE-1275"],
    hint: "CORS, security headers, cookie flags, debug, GraphQL introspection.",
  },
  {
    id: "API9",
    title: "Improper inventory management",
    judgment: true,
    hint: "Undocumented/legacy/versioned endpoints, non-prod hosts — inventory, not code.",
  },
  {
    id: "API10",
    title: "Unsafe consumption of APIs",
    kinds: ["ssrf", "deserialize", "CWE-295"],
    judgment: true,
    hint: "Trusting upstream API data: TLS verification off, unsafe deserialization of responses.",
  },
];

// OWASP MASVS (mobile). ultrasec parses Swift/Kotlin/Java, so it speaks to the
// code-level controls; RESILIENCE (anti-tampering/obfuscation) is out of reach.
const MASVS: AsvsCategory[] = [
  {
    id: "STORAGE",
    title: "Data storage & privacy",
    kinds: ["secret", "privacy", "CWE-798"],
    judgment: true,
    hint: "Secrets/PII in code or insecure local storage; logs leaking sensitive data.",
  },
  {
    id: "CRYPTO",
    title: "Cryptography",
    kinds: ["crypto", "random", "CWE-327", "CWE-328", "CWE-330", "CWE-798", "CWE-521"],
    judgment: true,
    hint: "Weak algorithms, hardcoded/weak keys, predictable IV/nonce, insecure randomness.",
  },
  {
    id: "AUTH",
    title: "Authentication & authorization",
    kinds: ["authz", "CWE-287", "CWE-347", "CWE-613"],
    judgment: true,
    hint: "Token verification/expiry, local vs. server-side authorization.",
  },
  {
    id: "NETWORK",
    title: "Network communication",
    kinds: ["CWE-295"],
    judgment: true,
    hint: "TLS verification disabled, hostname checks off, missing certificate pinning.",
  },
  {
    id: "PLATFORM",
    title: "Platform interaction",
    kinds: ["xss", "domxss", "config", "trustboundary", "CWE-942"],
    judgment: true,
    hint: "WebView JS bridges, exported components/IPC, insecure deep links.",
  },
  {
    id: "CODE",
    title: "Code quality",
    kinds: ["dep", "buffer", "command", "code", "deserialize"],
    judgment: true,
    hint: "Injection, memory safety, unsafe deserialization, outdated dependencies.",
  },
  {
    id: "RESILIENCE",
    title: "Resilience against reverse engineering",
    judgment: true,
    hint: "Anti-tampering, obfuscation, root/jailbreak detection — not a source-audit concern.",
  },
  { id: "PRIVACY", title: "Privacy", kinds: ["privacy"], judgment: true, hint: "Data minimisation, consent, third-party SDK data flows." },
];

// CWE Top 25 (2023). Keyed by CWE id — `kindsOf` now includes each finding's
// CWE, so a rank is `examined` the moment a finding carries it. Ranks the engine
// cannot enumerate (memory-lifetime, races) stay judgment.
const CWE_TOP25_2023: AsvsCategory[] = [
  { id: "1", title: "CWE-787 Out-of-bounds write", kinds: ["buffer", "CWE-787"], judgment: true, hint: "C/C++ buffer writes — `cppcheck`/manual review." },
  { id: "2", title: "CWE-79 Cross-site scripting", kinds: ["xss", "domxss", "CWE-79"], hint: "Reflected/stored/DOM XSS sinks enumerated." },
  { id: "3", title: "CWE-89 SQL injection", kinds: ["sql", "CWE-89"], hint: "SQL sinks enumerated by the taint walk." },
  { id: "4", title: "CWE-416 Use after free", kinds: ["CWE-416"], judgment: true, hint: "Memory lifetime — not enumerated; C/C++ review." },
  { id: "5", title: "CWE-78 OS command injection", kinds: ["command", "CWE-78"], hint: "Command sinks enumerated." },
  {
    id: "6",
    title: "CWE-20 Improper input validation",
    kinds: ["CWE-20"],
    judgment: true,
    hint: "Broad class — the whole taint catalog is a subset; judge per entry point.",
  },
  { id: "7", title: "CWE-125 Out-of-bounds read", kinds: ["buffer", "CWE-125"], judgment: true, hint: "C/C++ buffer reads — review." },
  { id: "8", title: "CWE-22 Path traversal", kinds: ["path", "CWE-22"], hint: "Path traversal / zip-slip sinks enumerated." },
  { id: "9", title: "CWE-352 Cross-site request forgery", kinds: ["CWE-352"], judgment: true, hint: "Missing CSRF token/state on state-changing routes." },
  {
    id: "10",
    title: "CWE-434 Unrestricted upload",
    kinds: ["path", "CWE-434"],
    judgment: true,
    hint: "Upload type/size/AV policy — partly path, mostly judgment.",
  },
  {
    id: "11",
    title: "CWE-862 Missing authorization",
    kinds: ["authz", "CWE-862"],
    judgment: true,
    hint: "Routes with no guard — run `ultrasec guards` to enumerate them, then the investigate lens.",
    requiresPass: "guards",
    hintWhenRan:
      "`ultrasec guards` enumerated every request handler and its visible guards — the remaining question is whether each guard binds the CALLER to the OBJECT (investigate lens).",
  },
  { id: "12", title: "CWE-476 NULL pointer dereference", kinds: ["CWE-476"], judgment: true, hint: "Not enumerated." },
  { id: "13", title: "CWE-287 Improper authentication", kinds: ["authz", "CWE-287", "CWE-347"], judgment: true, hint: "JWT/session verification correctness." },
  { id: "14", title: "CWE-190 Integer overflow", kinds: ["CWE-190"], judgment: true, hint: "Not enumerated." },
  { id: "15", title: "CWE-502 Deserialization of untrusted data", kinds: ["deserialize", "CWE-502"], hint: "Unsafe deserialization sinks enumerated." },
  { id: "16", title: "CWE-77 Command injection", kinds: ["command", "argv", "CWE-77"], hint: "Command/argument injection sinks enumerated." },
  { id: "17", title: "CWE-119 Improper restriction of memory buffer", kinds: ["buffer", "CWE-119"], judgment: true, hint: "C/C++ memory bounds." },
  { id: "18", title: "CWE-798 Use of hard-coded credentials", kinds: ["secret", "CWE-798"], hint: "Secret scanners + auth-token detector." },
  { id: "19", title: "CWE-918 Server-side request forgery", kinds: ["ssrf", "CWE-918"], hint: "SSRF sinks enumerated." },
  {
    id: "20",
    title: "CWE-306 Missing authentication for critical function",
    kinds: ["authz", "CWE-306"],
    judgment: true,
    hint: "Sensitive endpoints with no auth — run `ultrasec guards` to enumerate every handler and the guards visible in its scope.",
    requiresPass: "guards",
    hintWhenRan:
      "`ultrasec guards` ran: every request handler is enumerated with its visible guards. An `unguarded` row that nobody adjudicated is still an open question.",
  },
  { id: "21", title: "CWE-362 Race condition", kinds: ["CWE-362"], judgment: true, hint: "TOCTOU/balance races — not enumerated; investigate lens." },
  { id: "22", title: "CWE-269 Improper privilege management", kinds: ["authz", "CWE-269"], judgment: true, hint: "Privilege escalation paths — investigate." },
  { id: "23", title: "CWE-94 Code injection", kinds: ["code", "CWE-94"], hint: "Code-eval sinks enumerated." },
  {
    id: "24",
    title: "CWE-863 Incorrect authorization",
    kinds: ["authz", "CWE-863"],
    judgment: true,
    hint: "Wrong (not missing) authz decision — investigate.",
  },
  {
    id: "25",
    title: "CWE-276 Incorrect default permissions",
    kinds: ["config", "CWE-276"],
    judgment: true,
    hint: "World-readable files, permissive defaults — config/IaC.",
  },
];

/** All selectable coverage standards. `asvs` is the default and unchanged. */
export const STANDARDS: Record<string, StandardPack> = {
  asvs: { id: "asvs", title: "OWASP ASVS", categories: ASVS_CATEGORIES },
  "owasp-top10": { id: "owasp-top10", title: "OWASP Top 10 (2021)", categories: OWASP_TOP10_2021 },
  "owasp-api-top10": { id: "owasp-api-top10", title: "OWASP API Security Top 10 (2023)", categories: OWASP_API_TOP10_2023 },
  masvs: { id: "masvs", title: "OWASP MASVS (mobile)", categories: MASVS },
  "cwe-top25": { id: "cwe-top25", title: "CWE Top 25 (2023)", categories: CWE_TOP25_2023 },
};

/** The default standard, scored when `--standard` is not given. */
export const DEFAULT_STANDARD = "asvs";

/**
 * Back-compat: the ASVS chapter list, byte-for-byte as before the standards seam
 * existed. Callers and tests that import `ASVS` keep working unchanged.
 */
export const ASVS = ASVS_CATEGORIES;

export interface CoverageRow {
  id: string;
  title: string;
  state: CoverageState;
  /** Findings that landed in this category. */
  hits: number;
  judgment: boolean;
  hint: string;
}

function kindsOf(f: Finding): string[] {
  // A finding proves coverage of any class named by its category, its sink kind,
  // or its CWE id — the last is what lets a CWE-keyed standard (Top 10, CWE Top
  // 25) score the config/auth detectors without inventing taint sink kinds.
  return [f.category, f.sink?.kind, f.cwe].filter((x): x is string => Boolean(x));
}

/** The kinds a run enumerated — every category, sink kind and CWE its findings
 *  carry. Shared by the `coverage` command and the report renderer so the two
 *  can never disagree about what "engine covered" means. */
export function enumeratedKindsOf(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap(kindsOf))];
}

/**
 * Score coverage from the dossier alone, against `standardId` (default ASVS).
 * `enumeratedKinds` is what the run actually enumerated (the kinds present in the
 * findings), so a class the engine covers but this repo never exercised still
 * counts as looked-at — the walk ran, it just found nothing.
 */
export function buildCoverage(dossier: Dossier, enumeratedKinds: string[] = [], standardId: string = DEFAULT_STANDARD): CoverageRow[] {
  const pack = STANDARDS[standardId] ?? STANDARDS[DEFAULT_STANDARD]!;
  const enumerated = new Set(enumeratedKinds);
  return pack.categories.map((c) => {
    const hits = dossier.findings.filter((f) => (c.kinds ?? []).some((k) => kindsOf(f).includes(k))).length;
    const engineCovers = (c.kinds ?? []).some((k) => enumerated.has(k));
    const state: CoverageState = hits > 0 ? "examined" : engineCovers ? "engine" : "unexamined";
    // `undefined` from an older dossier means "unknown", so the default advice
    // stands — only a manifest that positively records the pass swaps it out.
    const ranIt = c.requiresPass ? dossier.manifest.passes?.[c.requiresPass] === true : false;
    const hint = ranIt && c.hintWhenRan ? c.hintWhenRan : c.hint;
    return { id: c.id, title: c.title, state, hits, judgment: !!c.judgment, hint };
  });
}

const MARK: Record<CoverageState, string> = {
  engine: "🔎 enumerated",
  examined: "✅ examined",
  unexamined: "⬜ **not examined**",
};

/**
 * Scanners that were supposed to run and did not, phrased as the coverage loss
 * they are.
 *
 * `toolStatus` has always recorded this, in the manifest, where a reader has to
 * go looking. On the first large audit three of nine scanners died — all three
 * on docker — and one of them was checkov, so the run had NO infrastructure-
 * as-code coverage at all. The single worst finding of that audit lived in a
 * Kubernetes SQL file. The report never said the pass was missing, and a short
 * IaC section read exactly like a clean one.
 */
function failedToolLines(dossier?: Dossier): string[] {
  const failed = (dossier?.manifest.toolStatus ?? []).filter((s) => s.status === "failed");
  if (!failed.length) return [];
  return [
    `### Scanners that failed (${failed.length})`,
    "",
    `Each of these is a hole in the table above, not a category with nothing in it. Re-run them`,
    `before treating any row they feed as examined.`,
    "",
    ...failed.map((s) => `- **${s.name}** — ${s.note ?? "run failed"}`),
    "",
  ];
}

export function renderCoverageMd(rows: CoverageRow[], standardTitle: string = "OWASP ASVS", dossier?: Dossier): string {
  const unexamined = rows.filter((r) => r.state === "unexamined");
  const judgment = rows.filter((r) => r.judgment && r.state !== "examined");
  const L: string[] = [`## Coverage (${standardTitle})`, ""];
  L.push(`What this audit looked at, and what it did not. A category marked **not examined** is not`);
  L.push(`a clean bill of health — it is a gap in the audit, and it belongs in the report.`);
  L.push("");
  L.push(...failedToolLines(dossier));
  L.push(`| | category | state | findings |`);
  L.push(`|---|---|---|---|`);
  for (const r of rows) L.push(`| ${r.id} | ${r.title} | ${MARK[r.state]} | ${r.hits || "—"} |`);
  L.push("");
  if (unexamined.length) {
    L.push(`### Not examined (${unexamined.length})`);
    L.push("");
    for (const r of unexamined) L.push(`- **${r.id} ${r.title}** — ${r.hint}`);
    L.push("");
  }
  if (judgment.length) {
    L.push(`### Answer these explicitly (${judgment.length})`);
    L.push("");
    L.push(`No deterministic signal can establish coverage here. For each, write either a finding or`);
    L.push(`one line saying **why it does not apply to this repo** — "not applicable" without a`);
    L.push(`reason is how coverage silently shrinks between audits.`);
    L.push("");
    for (const r of judgment) L.push(`- **${r.id} ${r.title}** — ${r.hint}`);
    L.push("");
  }
  return L.join("\n") + "\n";
}
