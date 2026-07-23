import { existsSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import type { Finding } from "../types.js";
import type { ToolAdapter } from "./run.js";
import { makeToolFinding, normalizeSeverity, firstCwe, cvesIn, parseJsonStream } from "./normalize.js";
import { detect } from "./registry.js";

// Native package-manager registry audits (npm/pnpm/yarn) — the vulnerability
// data every JS project already has a client for, no extra scanner install.
// All three query the registry on every run (network: true, skipped under
// --offline) and all exit non-zero when they find something (the runner
// already recovers stdout on non-zero exit — see src/tools/run.ts `exec`).
//
// v1 limitation: only the ROOT lockfile is audited (no monorepo workspace
// sub-lockfile walk) — trivy/osv-scanner already cover that recursively, so
// this is a documented gap rather than a silent one.

/** Extract a GHSA slug ("GHSA-xxxx-xxxx-xxxx") out of an advisory URL, if any. */
function ghsaFromUrl(url: unknown): string | undefined {
  const m = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i.exec(String(url ?? ""));
  return m ? m[0].toUpperCase() : undefined;
}

function parseJson(raw: string): any {
  try {
    return JSON.parse(raw || "{}");
  } catch {
    return null;
  }
}

// ── npm 6 / pnpm shared advisory shape ──────────────────────────────────────
// `{advisories: {"<id>": {module_name, findings: [{version}], severity, title,
// url, cves?, cwe?, github_advisory_id?}}}`. pnpm's own audit emits this exact
// legacy shape regardless of the pnpm version installed. Also reused by the
// yarn-classic dialect below, one advisory object at a time.

function npmV6AdvisoryFinding(tool: string, id: string, a: any, lockfile: string): Finding {
  const pkg = a?.module_name;
  const version = (a?.findings ?? [])[0]?.version;
  const ghsa = (a?.github_advisory_id ? String(a.github_advisory_id).toUpperCase() : undefined) || ghsaFromUrl(a?.url);
  const cves = [...(a?.cves ?? []), ...cvesIn(a?.title, a?.url)];
  const aliases = [ghsa, ...cves].filter(Boolean) as string[];
  // Prefer a cross-referenceable id (GHSA/CVE) as the `ident` — npm's own
  // internal numeric advisory id (module-private, no other tool ever reports
  // it) would otherwise leak into `aliases` via makeToolFinding as pure noise.
  const ident = ghsa || cves[0] || String(a?.id ?? id);
  return makeToolFinding({
    tool,
    category: "dep",
    ident,
    title: a?.title || `${pkg}: advisory ${id}`,
    severity: normalizeSeverity(a?.severity, "medium"),
    message: `${pkg}${version ? `@${version}` : ""}: ${a?.title || id}`,
    file: lockfile,
    cwe: firstCwe(a?.cwe),
    references: [a?.url].filter(Boolean),
    pkg,
    version,
    aliases,
  });
}

/** npm 6 AND pnpm shape. `tool` names the producing adapter (npm-audit vs
 *  pnpm-audit) so `sources`/`tool` on the resulting findings stay accurate. */
export function parseNpmV6Advisories(data: any, lockfile: string, tool: string): Finding[] {
  const advisories = data?.advisories;
  if (!advisories || typeof advisories !== "object") return [];
  const out: Finding[] = [];
  for (const id of Object.keys(advisories)) {
    const a = advisories[id];
    if (!a) continue;
    out.push(npmV6AdvisoryFinding(tool, id, a, lockfile));
  }
  return out;
}

// ── npm 7+ shape ─────────────────────────────────────────────────────────────
// `{auditReportVersion: 2, vulnerabilities: {"<name>": {severity, via: [...]}}}`.
// Each `via` entry is either a nested advisory object OR a bare string naming a
// transitive dependency that carries the vuln further up the tree — those
// string pointers are NOT a distinct advisory and must be skipped, or the same
// advisory would be double-counted once per hop.

/** npm 7+ (`auditReportVersion: 2`) shape. Always attributed to npm-audit —
 *  only npmAudit dispatches to this shape. */
export function parseNpmV7(data: any, lockfile: string): Finding[] {
  const vulns = data?.vulnerabilities;
  if (!vulns || typeof vulns !== "object") return [];
  const out: Finding[] = [];
  for (const name of Object.keys(vulns)) {
    const v = vulns[name];
    if (!v) continue;
    for (const via of v.via ?? []) {
      // String entries are transitive pointers, not advisory objects — skip.
      if (!via || typeof via !== "object") continue;
      const pkg = via.name || name;
      const ghsa = ghsaFromUrl(via.url);
      const cves = cvesIn(via.title, via.url);
      const aliases = [ghsa, ...cves].filter(Boolean) as string[];
      const ident = ghsa || cves[0] || String(via.source ?? `${pkg}:${via.title ?? ""}`);
      out.push(
        makeToolFinding({
          tool: "npm-audit",
          category: "dep",
          ident,
          title: via.title || `${pkg} advisory`,
          // via.severity is the specific advisory's label; fall back to the
          // parent vulnerabilities[name].severity when the via entry omits it.
          severity: normalizeSeverity(via.severity ?? v.severity, "medium"),
          // No reliably-present installed version in this shape — the range
          // the advisory applies to carries the same signal in the message.
          message: `${pkg}${via.range ? `@${via.range}` : ""}: ${via.title || ident}`,
          file: lockfile,
          cwe: firstCwe(via.cwe),
          references: [via.url].filter(Boolean),
          pkg,
          aliases,
        }),
      );
    }
  }
  return out;
}

/** Resolve which npm lockfile is present at the repo root (package-lock.json
 *  is preferred; npm-shrinkwrap.json is the legacy alternative). */
function npmLockfileName(repo: string): string {
  if (!existsSync(join(repo, "package-lock.json")) && existsSync(join(repo, "npm-shrinkwrap.json"))) return "npm-shrinkwrap.json";
  return "package-lock.json";
}

export const npmAudit: ToolAdapter = {
  name: "npm-audit",
  category: "dep",
  network: true,
  command: () => (detect("npm").installed ? ["npm"] : null),
  applicable: (repo) => (existsSync(join(repo, "package-lock.json")) || existsSync(join(repo, "npm-shrinkwrap.json")) ? null : "no package-lock.json"),
  argv: () => ["audit", "--json"],
  parse(raw, repo): Finding[] {
    const data = parseJson(raw);
    if (!data || typeof data !== "object") return [];
    const lockfile = npmLockfileName(repo);
    if (data.auditReportVersion === 2) return parseNpmV7(data, lockfile);
    if (data.advisories) return parseNpmV6Advisories(data, lockfile, "npm-audit");
    return [];
  },
};

export const pnpmAudit: ToolAdapter = {
  name: "pnpm-audit",
  category: "dep",
  network: true,
  command: () => (detect("pnpm").installed ? ["pnpm"] : null),
  applicable: (repo) => (existsSync(join(repo, "pnpm-lock.yaml")) ? null : "no pnpm-lock.yaml"),
  argv: () => ["audit", "--json"],
  parse(raw): Finding[] {
    const data = parseJson(raw);
    if (!data || typeof data !== "object") return [];
    // pnpm's registry audit emits the same legacy shape as npm 6, regardless
    // of the pnpm version installed.
    return parseNpmV6Advisories(data, "pnpm-lock.yaml", "pnpm-audit");
  },
};

// ── yarn: classic (v1) vs berry (v2+) — different binary AND different output
// dialect, both gated behind one real-version probe ───────────────────────────

let yarnMajorCache: number | null | undefined; // undefined = not probed yet this process

/** `yarn --version` → major version, or null when yarn is absent / the probe
 *  fails / the output doesn't parse. Never throws. Memoized: probed once per
 *  process so command()/argv() (both called per run) always agree. */
export function yarnMajor(): number | null {
  if (yarnMajorCache !== undefined) return yarnMajorCache;
  try {
    const out = execFileSync("yarn", ["--version"], { stdio: ["ignore", "pipe", "ignore"], timeout: 5000 })
      .toString()
      .trim();
    const major = Number.parseInt(out.split(".")[0] ?? "", 10);
    yarnMajorCache = Number.isFinite(major) ? major : null;
  } catch {
    yarnMajorCache = null;
  }
  return yarnMajorCache;
}

function yarnBerryFinding(entry: any): Finding | null {
  const pkg = entry?.value;
  if (typeof pkg !== "string" || !pkg) return null;
  const c = entry?.children ?? {};
  const ghsa = ghsaFromUrl(c.URL);
  const cves = cvesIn(c.Issue, c.URL);
  const aliases = [ghsa, ...cves].filter(Boolean) as string[];
  const treeVersions = c["Tree Versions"];
  const version = Array.isArray(treeVersions) ? treeVersions[0] : undefined;
  const ident = String(c.ID ?? ghsa ?? cves[0] ?? pkg);
  const vulnerable = c["Vulnerable Versions"];
  return makeToolFinding({
    tool: "yarn-audit",
    category: "dep",
    ident,
    title: c.Issue || `${pkg} advisory`,
    severity: normalizeSeverity(c.Severity, "medium"),
    message: `${pkg}${version ? `@${version}` : ""}: ${c.Issue || ident}` + (vulnerable ? ` (vulnerable: ${vulnerable})` : ""),
    file: "yarn.lock",
    references: [c.URL].filter(Boolean),
    pkg,
    version,
    aliases,
  });
}

export const yarnAudit: ToolAdapter = {
  name: "yarn-audit",
  category: "dep",
  network: true,
  streaming: true,
  applicable: (repo) => (existsSync(join(repo, "yarn.lock")) ? null : "no yarn.lock"),
  command: () => {
    const major = yarnMajor();
    if (major === null) return null;
    return major >= 2 ? ["yarn", "npm"] : ["yarn"];
  },
  argv: () => {
    const major = yarnMajor();
    return major !== null && major >= 2 ? ["audit", "--json", "--recursive"] : ["audit", "--json"];
  },
  parse(raw): Finding[] {
    try {
      const lines = raw ? (parseJsonStream(raw) as any[]) : [];
      const out: Finding[] = [];
      for (const m of lines) {
        if (!m || typeof m !== "object") continue;
        // classic: {type: "auditAdvisory", data: {advisory: {...npm-v6 shape}}}
        if (m.type === "auditAdvisory" && m.data?.advisory) {
          const a = m.data.advisory;
          out.push(npmV6AdvisoryFinding("yarn-audit", String(a.id ?? ""), a, "yarn.lock"));
          continue;
        }
        // berry: {value: "<pkg>", children: {ID, Issue, URL, Severity, ...}}
        if (typeof m.value === "string" && m.children && typeof m.children === "object") {
          const f = yarnBerryFinding(m);
          if (f) out.push(f);
        }
        // Anything else (auditSummary, info lines, …) is skipped silently.
      }
      return out;
    } catch {
      return [];
    }
  },
};
