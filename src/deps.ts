import { compareWithinStatus, rankScore } from "./rank.js";
import { SEVERITIES, type Finding, type Reachability, type Severity } from "./types.js";
import { byStr } from "./util.js";

// Dependency advisories, rolled up to the unit anyone actually acts on: the
// PACKAGE.
//
// A CVE list is not a work list. On the audit that prompted this, 190 dep
// findings were 190 rows — but `minimatch` alone held 7 of them, `axios` 6,
// `next` 9, and every one of those clusters is ONE upgrade. Printing them
// separately makes the report longer and the remediation no clearer, and it
// pushes the ~100 real source-to-sink flows off the first three screens.
//
// So the section prints one row per package — worst severity, how many
// advisories, the version to move to — and keeps every advisory under a fold.
// Nothing is dropped: `findings.json` still holds each finding individually,
// and the fold lists them with their ids. This is presentation, like
// `family.ts`, and the same rule applies: grouping is for READING, never for
// deciding. No verdict travels from a row to its members.

export interface PackageRow {
  /** Package name — the row's identity and the unit of remediation. */
  pkg: string;
  /** Every installed version the advisories were reported against. */
  versions: string[];
  /** Worst severity across the cluster. */
  worst: Severity;
  /** Best (highest) composite risk in the cluster — the sort key. */
  worstRisk: number;
  /** How many distinct advisories affect this package. */
  count: number;
  /** How many of them are in CISA KEV — known-exploited beats everything. */
  kev: number;
  /** Highest EPSS across the cluster, when any advisory is scored. */
  maxEpss?: number;
  /** Highest fixed version named by any advisory, when one is published. */
  fixedVersion?: string;
  /** Worst reachability: `runtime` outranks `unproven` outranks `toolchain`. */
  reachability?: Reachability;
  /** Every lockfile location, deduped. */
  locations: { file: string; line?: number; version?: string }[];
  /** The advisories themselves, in rank order — the fold's contents. */
  advisories: Finding[];
}

/**
 * The fixed version, from the field or from the prose that used to carry it.
 *
 * `fixedVersion` is populated at the adapter now, but a dossier written before
 * that lands only has `"minimatch@8.0.4: ... (fixed in 10.2.3)"` in `message`.
 * Re-rendering an existing run must not silently answer "no fix published" for
 * 187 of 190 advisories, so the prose is parsed as a fallback. New runs never
 * reach it.
 */
export function fixedVersionOf(f: Finding): string | undefined {
  if (f.fixedVersion) return f.fixedVersion;
  const m = /\(fixed in ([^)]+)\)/i.exec(f.message ?? "");
  return m ? m[1]!.trim() : undefined;
}

/** `runtime` is the case that matters; `toolchain` (a devDependency) the one
 *  that can wait. A cluster is as reachable as its most reachable member. */
const REACH_RANK: Record<Reachability, number> = { runtime: 0, unproven: 1, toolchain: 2 };

function worseReachability(a: Reachability | undefined, b: Reachability | undefined): Reachability | undefined {
  if (!a) return b;
  if (!b) return a;
  return REACH_RANK[a] <= REACH_RANK[b] ? a : b;
}

function worseSeverity(a: Severity, b: Severity): Severity {
  return SEVERITIES.indexOf(a) <= SEVERITIES.indexOf(b) ? a : b;
}

/** The locations an advisory cites: the merged set when the correlator built
 *  one, else the single flagged lockfile line. */
function locationsOf(f: Finding): { file: string; line?: number; version?: string }[] {
  if (f.locations?.length) return f.locations;
  if (f.sink) return [{ file: f.sink.file, line: f.sink.line, ...(f.version ? { version: f.version } : {}) }];
  return [];
}

/**
 * A package with no name still gets a row.
 *
 * Not every dep adapter sets `pkg` — a SARIF-sourced one may not. Bucketing
 * those under a single "(unnamed)" heading would merge unrelated advisories
 * into one fake upgrade, so each falls back to its own id: one row, honest
 * about being ungrouped, instead of a cluster that isn't one.
 */
const UNGROUPED = "\u0000";

function keyOf(f: Finding): string {
  return f.pkg?.trim() || UNGROUPED + f.id;
}

/**
 * Compare two version strings the way a release train orders them.
 *
 * Three things a naive string compare gets wrong, each of which would point a
 * reader at an upgrade that does not fix their advisory:
 *   - `"1.10.0" > "1.9.0"` is false as a string and true as a version;
 *   - `"1.0"` and `"1.0.0"` are the same release, so a missing segment is 0;
 *   - `"1.0.0-rc1"` precedes `"1.0.0"`, so a pre-release ranks BELOW its final.
 *
 * Not a full semver implementation and it does not need to be: the inputs are
 * the fixed versions scanners emit, and the only question asked of them is
 * which is highest.
 */
export function compareVersions(a: string, b: string): number {
  const split = (v: string): { core: number[]; pre: string } => {
    const at = v.search(/[-+]/);
    const core = (at === -1 ? v : v.slice(0, at)).split(".").map((x) => Number.parseInt(x, 10));
    return { core, pre: at === -1 ? "" : v.slice(at + 1) };
  };
  const va = split(a);
  const vb = split(b);
  for (let i = 0; i < Math.max(va.core.length, vb.core.length); i++) {
    // An absent segment is zero: 1.0 and 1.0.0 are one release.
    const na = va.core[i] ?? 0;
    const nb = vb.core[i] ?? 0;
    if (!Number.isFinite(na) || !Number.isFinite(nb)) {
      const c = byStr(String(va.core[i] ?? ""), String(vb.core[i] ?? ""));
      if (c) return c;
      continue;
    }
    if (na !== nb) return na - nb;
  }
  if (va.pre === vb.pre) return 0;
  // A release outranks its own pre-releases; two pre-releases order by name.
  if (!va.pre) return 1;
  if (!vb.pre) return -1;
  return byStr(va.pre, vb.pre);
}

/** Roll dependency findings up per package, worst risk first. */
export function groupAdvisoriesByPackage(findings: readonly Finding[]): PackageRow[] {
  const byPkg = new Map<string, Finding[]>();
  for (const f of findings) {
    const k = keyOf(f);
    const list = byPkg.get(k);
    if (list) list.push(f);
    else byPkg.set(k, [f]);
  }

  const rows: PackageRow[] = [];
  for (const [key, group] of byPkg) {
    const advisories = group.slice().sort(compareWithinStatus);
    const lead = advisories[0]!;
    const versions = [...new Set(group.flatMap((f) => [f.version, ...locationsOf(f).map((l) => l.version)]).filter((v): v is string => Boolean(v)))].sort(
      byStr,
    );
    const locByKey = new Map<string, { file: string; line?: number; version?: string }>();
    for (const f of group) for (const l of locationsOf(f)) locByKey.set(`${l.version ?? ""}|${l.file}|${l.line ?? ""}`, l);
    const epss = group.map((f) => f.epss).filter((e): e is number => typeof e === "number");
    const fixes = [...new Set(group.map(fixedVersionOf).filter((v): v is string => Boolean(v)))];
    const reach = group.map((f) => f.reachability).reduce<Reachability | undefined>(worseReachability, undefined);

    rows.push({
      pkg: key.startsWith(UNGROUPED) ? (lead.pkg ?? lead.title) : key,
      versions,
      worst: group.reduce<Severity>((s, f) => worseSeverity(s, f.severity), "info"),
      worstRisk: Math.max(...group.map(rankScore)),
      count: group.length,
      kev: group.filter((f) => f.kev).length,
      ...(epss.length ? { maxEpss: Math.max(...epss) } : {}),
      // Several advisories on one package name several fixed versions; the
      // highest is the one upgrade that clears them all.
      ...(fixes.length ? { fixedVersion: fixes.reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b)) } : {}),
      ...(reach ? { reachability: reach } : {}),
      locations: [...locByKey.entries()].sort((a, b) => byStr(a[0], b[0])).map(([, l]) => l),
      advisories,
    });
  }

  return rows.sort(
    (a, b) => b.worstRisk - a.worstRisk || SEVERITIES.indexOf(a.worst) - SEVERITIES.indexOf(b.worst) || b.count - a.count || byStr(a.pkg, b.pkg),
  );
}
