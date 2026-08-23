import type { Category, Finding, Severity } from "./types.js";

// Which SURFACE a finding belongs to — the axis the report is organised on.
//
// ── Why this module exists ─────────────────────────────────────────────────
//
// `category` records HOW a finding was surfaced (types.ts:78). What a reader
// asks first is a different question: is this a bug in code I WROTE, or an
// advisory about code I INSTALLED? Those are different documents. One is read
// by opening the file and following the flow; the other is worked as a ranked
// list, stopping when the rest fall below the bar — that is exactly what
// references/supply-chain.md prescribes, and the report never reflected it.
//
// The audit that prompted this printed 882 candidates in one flat table ranked
// by composite risk. Because the KEV floor pins an exploited CVE at 95
// (tools/scoring.ts), 190 `pnpm-lock.yaml:1` rows opened the report and the
// ~100 real cross-file flows under `targets/` were scattered through it. Every
// fact was present; the document answered the wrong question first.
//
// Three surfaces, not two. Secrets and IaC/CI config live in the repo, so they
// are the author's problem and not a vendor's — but they are read differently
// from a data-flow: a committed key is a rotation, a permissive CORS header is
// a config diff. Folding them into `code` would bury the flows again, this time
// under 42 secret hits.

export const SURFACES = ["code", "supply", "deps"] as const;
export type Surface = (typeof SURFACES)[number];

export const SURFACE_TITLE: Record<Surface, string> = {
  code: "Your source code",
  supply: "Secrets & configuration",
  deps: "Dependency advisories",
};

/**
 * The surface a category belongs to.
 *
 * Exhaustive over the closed `CATEGORIES` vocabulary — a new category is a
 * compile error here, which is the point: adding one without deciding where it
 * is READ would silently drop it into whatever the fallback happened to be.
 */
const SURFACE_OF_CATEGORY: Record<Category, Surface> = {
  taint: "code",
  sast: "code",
  authz: "code",
  crypto: "code",
  logs: "code",
  privacy: "code",
  other: "code",
  secret: "supply",
  config: "supply",
  dep: "deps",
};

/** A finding with a malformed category is read as `code` — the surface that
 *  gets looked at. Hiding an unclassifiable finding in a collapsed dependency
 *  fold is the one outcome that must not happen. */
export function surfaceOf(f: Finding): Surface {
  return SURFACE_OF_CATEGORY[f.category] ?? "code";
}

/** Split findings by surface, preserving the caller's order within each. */
export function bySurface(findings: readonly Finding[]): Record<Surface, Finding[]> {
  const out: Record<Surface, Finding[]> = { code: [], supply: [], deps: [] };
  for (const f of findings) out[surfaceOf(f)].push(f);
  return out;
}

/** Severities that must be READ rather than triaged from a list. */
const MUST_READ: readonly Severity[] = ["critical", "high"];

/**
 * The candidates that make a run a dump rather than an audit.
 *
 * Source-code candidates at HIGH or CRITICAL that nobody adjudicated. A
 * dependency advisory left `open` is a legitimate triage outcome — the ladder
 * in references/supply-chain.md says to work the list in risk order and stop
 * when the rest are below the bar. An unread cross-file flow is not: deciding
 * it requires opening the file, and no one did.
 */
export function unadjudicatedCode(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => f.status === "open" && surfaceOf(f) !== "deps" && MUST_READ.includes(f.severity));
}
