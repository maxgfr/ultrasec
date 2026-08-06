import type { Dossier } from "./store.js";
import type { Finding } from "./types.js";

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
  /** Sink kinds / categories whose presence proves the class was enumerated. */
  kinds?: string[];
  /** True when no deterministic signal can establish coverage — you must say. */
  judgment?: boolean;
  /** What answering it well requires. */
  hint: string;
}

/**
 * OWASP ASVS v4 chapters, trimmed to the ones a source audit can speak to.
 * Deliberately not the full 14: claiming coverage of "V10 Malicious Code" from a
 * taint walk would be exactly the coverage theatre this file exists to avoid.
 */
export const ASVS: AsvsCategory[] = [
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
  { id: "V7", title: "Error handling & logging", kinds: ["logs"], hint: "Needs `scan --log-hygiene` to be enumerated at all (CWE-117/532)." },
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
  return [f.category, f.sink?.kind].filter((x): x is string => Boolean(x));
}

/**
 * Score coverage from the dossier alone. `engineKinds` is what the run actually
 * enumerated (the catalog kinds present in the findings), so a class the engine
 * covers but this repo never exercised still counts as looked-at — the walk ran,
 * it just found nothing.
 */
export function buildCoverage(dossier: Dossier, enumeratedKinds: string[] = []): CoverageRow[] {
  const enumerated = new Set(enumeratedKinds);
  return ASVS.map((c) => {
    const hits = dossier.findings.filter((f) => (c.kinds ?? []).some((k) => kindsOf(f).includes(k))).length;
    const engineCovers = (c.kinds ?? []).some((k) => enumerated.has(k));
    const state: CoverageState = hits > 0 ? "examined" : engineCovers ? "engine" : "unexamined";
    return { id: c.id, title: c.title, state, hits, judgment: !!c.judgment, hint: c.hint };
  });
}

const MARK: Record<CoverageState, string> = {
  engine: "🔎 enumerated",
  examined: "✅ examined",
  unexamined: "⬜ **not examined**",
};

export function renderCoverageMd(rows: CoverageRow[]): string {
  const unexamined = rows.filter((r) => r.state === "unexamined");
  const judgment = rows.filter((r) => r.judgment && r.state !== "examined");
  const L: string[] = [`## Coverage (OWASP ASVS)`, ""];
  L.push(`What this audit looked at, and what it did not. A category marked **not examined** is not`);
  L.push(`a clean bill of health — it is a gap in the audit, and it belongs in the report.`);
  L.push("");
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
