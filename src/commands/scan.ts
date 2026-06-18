import { resolve, join, relative } from "node:path";
import { existsSync } from "node:fs";
import { flagStr, flagBool, listFlag, numFlag, own, println, eprintln, byStr, type ParsedArgs } from "../util.js";
import { scanRepo, scanRepoCached } from "../scan.js";
import { buildGraph, reverseDependents } from "../graph.js";
import { enumerateTaint } from "../taint.js";
import { enumerateSinkCandidates } from "../sinks.js";
import { changedFiles } from "../git.js";
import { addProvenance } from "../provenance.js";
import { loadScanCache, saveScanCache } from "../cache.js";
import { orchestrate } from "../tools/run.js";
import { enrichFindings } from "../tools/scoring.js";
import { ADAPTERS } from "../tools/index.js";
import { writeDossier, loadDossier, mergeDossier, countBySeverity, type Dossier } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Finding, type Manifest } from "../types.js";

// Budget presets scale call-graph depth × candidate breadth. `standard` reproduces
// the historical defaults (6 hops / 1000 candidates).
const BUDGETS: Record<string, { maxDepth: number; maxCandidates: number }> = {
  quick: { maxDepth: 3, maxCandidates: 200 },
  standard: { maxDepth: 6, maxCandidates: 1000 },
  thorough: { maxDepth: 8, maxCandidates: 5000 },
};

const REVDEP_DEPTH = 2; // how far to expand changed files to their callers for --diff

// `ultrasec scan --repo <dir> [--out .ultrasec] [--json]`
// The mechanical pass: scan → build link-graph → enumerate cross-file taint
// candidates → run external scanners (correlated across tools) → enrich CVEs
// with EPSS/KEV risk → write the audit dossier. Scales to huge repos via
// --scope/--include/--exclude/--max-files and incrementally via --diff/--merge.
export async function runScan(args: ParsedArgs): Promise<number> {
  const repo = resolve(flagStr(args, "repo") ?? ".");
  const out = resolve(flagStr(args, "out") ?? ".ultrasec");

  // Scope knobs (large-repo focus): prune the walk so a huge tree is never fully read.
  const scope = listFlag(args, "scope");
  const include = listFlag(args, "include");
  const exclude = listFlag(args, "exclude");
  const maxFiles = numFlag(args, "max-files");
  const gitignore = flagBool(args, "gitignore");

  // Budget knobs: rank-then-cap taint candidates; explicit flags override the preset.
  // own() guards against a `--budget constructor`-style prototype-member name.
  const budgetName = flagStr(args, "budget");
  const preset = own(BUDGETS, budgetName ?? "standard") ?? BUDGETS.standard!;
  const maxDepth = numFlag(args, "max-depth") ?? preset.maxDepth;
  const maxCandidates = numFlag(args, "max-candidates") ?? preset.maxCandidates;

  // Incremental: --diff/--since <ref> scans only files changed since the ref plus
  // their reverse-dependents (the call sites that reach them), folding into --merge.
  const diffRef = flagStr(args, "diff") ?? flagStr(args, "since");
  let effectiveScope = scope;
  let diffNote: string | undefined;
  if (diffRef) {
    const changedRaw = changedFiles(repo, diffRef);
    if (changedRaw === null) {
      eprintln(`ultrasec: --diff/--since needs a git work tree and a resolvable ref (got '${diffRef}'). Aborting — no silent full scan.`);
      return 2;
    }
    // Drop the audit's own output DIRECTORY from the changed set (it shows up as
    // untracked when --out lives inside the repo) so a diff scan never re-scans its
    // own dossier. We only filter by the out-dir PREFIX — never by artifact names,
    // which could collide with real source files. When --out is the repo root we
    // can't prefix-filter, but the dossier files are non-source and are skipped by
    // language detection anyway, so leaving them in the changed set is harmless.
    const relOut = relative(repo, out);
    const changed =
      relOut && relOut !== "." && !relOut.startsWith("..")
        ? changedRaw.filter((f) => f !== relOut && !f.startsWith(relOut + "/"))
        : changedRaw;
    let targets = changed;
    if (existsSync(join(out, "graph.json"))) {
      try {
        targets = reverseDependents(loadDossier(out).graph, changed, REVDEP_DEPTH);
        diffNote = `--diff ${diffRef}: ${changed.length} changed → ${targets.length} file(s) incl. reverse-deps`;
      } catch {
        diffNote = `--diff ${diffRef}: ${changed.length} changed file(s) (prior dossier unreadable; reverse-deps skipped)`;
      }
    } else {
      diffNote = `--diff ${diffRef}: ${changed.length} changed file(s) — run a full scan first to include reverse-dependents`;
    }
    if (targets.length === 0) {
      println(`ultrasec scan: no changed files since ${diffRef} — nothing to do.`);
      return 0;
    }
    // Exact file paths used as scope entries match those files precisely while still
    // pruning unrelated directory trees during the walk.
    effectiveScope = [...(scope ?? []), ...targets];
  }

  const scanOpts = { scope: effectiveScope, include, exclude, maxFiles, gitignore };
  const resume = flagBool(args, "resume");
  const cache = resume ? loadScanCache(out) : undefined;
  const scan = cache ? scanRepoCached(repo, scanOpts, cache) : scanRepo(repo, scanOpts);
  const graph = buildGraph(scan);
  const taint = enumerateTaint(scan, graph, { maxDepth, maxCandidates });
  const taintFindings = taint.findings;

  // Orphan-sink recall (opt-in `--sinks`): dangerous sinks the source-gated taint
  // BFS can't connect to a source still warrant a look. Emitted as low-confidence
  // `sast` candidates, de-duped against the taint findings, capped + reported.
  const sinksOn = flagBool(args, "sinks");
  const sinkCand = sinksOn
    ? enumerateSinkCandidates(scan, taintFindings, { maxCandidates })
    : { findings: [] as Finding[], truncated: 0, total: 0 };

  // External tools: `--tools none`/`--no-tools` skips; `--tools a,b` selects; absent =
  // auto. A SCOPED/diff pass skips them by default (don't re-run Trivy on a drill-down);
  // pass `--tools auto` to force them.
  const scopedScan = !!((effectiveScope && effectiveScope.length) || include?.length || exclude?.length || diffRef);
  const toolsFlag = flagStr(args, "tools");
  const toolsAutoSkipped = scopedScan && toolsFlag === undefined && !flagBool(args, "no-tools");
  const skipTools = flagBool(args, "no-tools") || toolsFlag === "none" || toolsAutoSkipped;
  const which = toolsFlag && toolsFlag !== "auto" && toolsFlag !== "none" ? toolsFlag.split(",").map((s) => s.trim()) : undefined;
  const useDocker = flagBool(args, "docker");
  const tool = skipTools ? { findings: [] as Finding[], toolsRun: [] as string[], results: [] } : orchestrate(ADAPTERS, repo, { which, useDocker });

  // Merge taint candidates, orphan-sink candidates, and tool findings (ids are
  // disjoint by construction).
  const merged = [...taintFindings, ...sinkCand.findings, ...tool.findings].sort((a, b) => byStr(a.id, b.id));

  // Enrich CVE-bearing findings with EPSS/KEV and compute a risk score on every
  // finding. Network-tolerant (cached feeds); `--no-enrich`/`--offline` skips it.
  const enrich = !(flagBool(args, "no-enrich") || flagBool(args, "offline"));
  const { findings: enriched, note: riskNote } = await enrichFindings(merged, { enabled: enrich });

  // Provenance (opt-in `--blame`/`--provenance`): deterministic git-blame author/
  // date + CODEOWNERS owner per finding — a triage signal, never a suppression
  // rule. Offline-tolerant: no git / no CODEOWNERS ⇒ findings pass through as-is.
  const blameOn = flagBool(args, "blame") || flagBool(args, "provenance");
  const findings = blameOn ? addProvenance(enriched, repo, { blame: true }) : enriched;

  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  // Never hide a capped run as a full one: record candidate + file-walk truncation.
  // Candidate truncation folds the taint and orphan-sink caps together.
  const truncatedCount = taint.truncated + sinkCand.truncated;
  const totalCandidates = taint.total + sinkCand.total;
  const truncation =
    truncatedCount > 0 || scan.truncated
      ? { candidates: truncatedCount, total: totalCandidates, ...(scan.truncated ? { files: true as const } : {}) }
      : undefined;
  const recordedScopes = [...(scope ?? []), ...(diffRef ? [`diff:${diffRef}`] : [])].sort(byStr);
  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Taint candidates are deterministic; external-tool results depend on installed scanners.",
    languages,
    toolsRun: tool.toolsRun,
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(truncation ? { truncation } : {}),
    ...(recordedScopes.length ? { scopes: recordedScopes } : {}),
  };

  const nextDossier: Dossier = { manifest, findings, graph };
  let final = nextDossier;
  let mergedNote = "";
  if (flagBool(args, "merge") && existsSync(join(out, "findings.json"))) {
    try {
      const prev = loadDossier(out);
      final = mergeDossier(prev, nextDossier);
      mergedNote = ` · merged into ${prev.findings.length} prior finding(s)`;
    } catch (e) {
      // Surface rather than hide — a present-but-unreadable dossier is a real problem.
      eprintln(`ultrasec: could not merge into the existing dossier at ${out} (${e instanceof Error ? e.message : String(e)}); writing a fresh dossier instead.`);
    }
  }
  writeDossier(out, final);
  if (cache) saveScanCache(out, cache);

  const fm = final.manifest;
  const fc = fm.counts.bySeverity;
  if (flagBool(args, "json")) {
    const kev = final.findings.filter((f) => f.kev).length;
    println(
      JSON.stringify(
        { out, counts: fm.counts, languages: fm.languages, files: scan.files.length, toolsRun: fm.toolsRun, kev, risk: riskNote, truncation, scopes: fm.scopes, diff: diffNote, sinks: sinksOn ? sinkCand.findings.length : undefined, merged: mergedNote.trim() || undefined },
        null,
        2,
      ),
    );
    return 0;
  }

  println(`ultrasec scan → ${out}${mergedNote}`);
  println(`  files scanned: ${scan.files.length}  ·  languages: ${languages.join(", ") || "—"}`);
  if (diffNote) println(`  ${diffNote}`);
  if (toolsAutoSkipped) {
    println(`  external scanners skipped in scoped mode — pass \`--tools auto\` to run them.`);
  } else if (!skipTools) {
    println(`  external tools run: ${tool.toolsRun.join(", ") || "none"}  (\`ultrasec tools\` to see/install more)`);
  }
  println(`  candidate findings: ${fm.counts.findings}  (crit ${fc.critical} · high ${fc.high} · med ${fc.medium} · low ${fc.low})  ·  ${taintFindings.length} taint${sinksOn ? ` + ${sinkCand.findings.length} sink` : ""} + ${tool.findings.length} tool this pass`);
  println(`  ${riskNote}`);
  if (truncation?.candidates) {
    println(`  ⚠️  showing top ${maxCandidates} of ${truncation.total} candidates — ${truncation.candidates} not shown. Raise --max-candidates or narrow --scope.`);
  }
  if (truncation?.files) {
    println(`  ⚠️  file walk hit --max-files (${maxFiles}) — some files were NOT scanned. Raise --max-files or narrow --scope.`);
  }
  if (!fm.counts.findings) {
    println(`  no taint candidates — still review the DOSSIER and run external tools (\`ultrasec tools\`).`);
  } else {
    println(`  next: read ${out}/DOSSIER.md, then \`ultrasec dossier <id> --run ${out}\` to adjudicate.`);
  }
  return 0;
}
