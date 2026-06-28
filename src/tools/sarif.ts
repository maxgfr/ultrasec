import type { Category, Finding, Severity } from "../types.js";
import { makeToolFinding, firstCwe, normalizeSeverity } from "./normalize.js";
import { deriveSeverity } from "./cvss.js";

// A reusable SARIF 2.1.0 → Finding[] parser. SARIF is the OASIS-standard static-
// analysis interchange format that bandit, gosec, cppcheck, hadolint, checkov,
// Kingfisher and most modern scanners can emit — so one parser turns any of them
// into a thin adapter (argv + a ruleId→CWE hint). It reads:
//   • severity  ← properties["security-severity"] (CVSS-like 0–10) else `level`.
//   • cwe       ← rule.properties.tags / .cwe (a CWE-NNN), else a caller default.
//   • location  ← the first result location's artifactLocation.uri + region.
//   • refs      ← rule helpUri.
// Robust to absent rules[], missing levels, and empty input (returns []).

export interface SarifOptions {
  tool: string;
  category: Category;
  /** CWE to use when a result/rule carries none (e.g. CWE-798 for secret tools). */
  defaultCwe?: string;
  /** Severity to use when neither security-severity nor level is present. */
  defaultSeverity?: Severity;
}

// SARIF `level` → ultrasec severity (normalizeSeverity already aliases these).
function levelSeverity(level: string | undefined, fallback: Severity): Severity {
  if (!level) return fallback;
  return normalizeSeverity(level, fallback);
}

function cweFromTags(tags: unknown): string | undefined {
  const arr = Array.isArray(tags) ? tags : [];
  for (const t of arr) {
    const cwe = firstCwe(typeof t === "string" ? t : "");
    if (cwe) return cwe;
  }
  return undefined;
}

export function parseSarif(raw: string, opts: SarifOptions): Finding[] {
  let data: any;
  try {
    data = JSON.parse(raw || "{}");
  } catch {
    return [];
  }
  const out: Finding[] = [];
  const fallbackSev = opts.defaultSeverity ?? "medium";

  for (const run of data?.runs ?? []) {
    const rules: any[] = run?.tool?.driver?.rules ?? [];
    const byId = new Map<string, any>();
    rules.forEach((r) => r?.id && byId.set(r.id, r));

    for (const res of run?.results ?? []) {
      const ruleId: string = res.ruleId ?? (typeof res.ruleIndex === "number" ? rules[res.ruleIndex]?.id : undefined) ?? "rule";
      const rule = byId.get(ruleId) ?? (typeof res.ruleIndex === "number" ? rules[res.ruleIndex] : undefined) ?? {};

      const loc = res.locations?.[0]?.physicalLocation ?? {};
      const file: string | undefined = loc.artifactLocation?.uri;
      const line: number | undefined = loc.region?.startLine;

      // security-severity (CVSS-like) wins; else SARIF level; else default.
      const secSev = res.properties?.["security-severity"] ?? rule.properties?.["security-severity"];
      const level = res.level ?? rule.defaultConfiguration?.level;
      const severity: Severity =
        secSev !== undefined && secSev !== null && String(secSev).trim() !== ""
          ? deriveSeverity(String(secSev), fallbackSev)
          : levelSeverity(level, fallbackSev);

      const cwe = cweFromTags(rule.properties?.tags) ?? cweFromTags(res.properties?.tags) ?? firstCwe(rule.properties?.cwe) ?? opts.defaultCwe;

      const message: string = res.message?.text ?? rule.shortDescription?.text ?? rule.fullDescription?.text ?? ruleId;
      const refs = [rule.helpUri, res.hostedViewerUri].filter((x): x is string => Boolean(x));

      out.push(
        makeToolFinding({
          tool: opts.tool,
          category: opts.category,
          ident: `${ruleId}:${file ?? ""}:${line ?? ""}`,
          title: ruleId,
          severity,
          message: file ? `${message} [${ruleId}] at ${file}:${line ?? "?"}` : `${message} [${ruleId}]`,
          file,
          line,
          cwe,
          references: refs.length ? refs : undefined,
        }),
      );
    }
  }
  return out;
}
