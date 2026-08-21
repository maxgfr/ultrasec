import { resolve, join, relative } from "node:path";
import { existsSync } from "node:fs";
import { flagStr, flagBool, listFlag, numFlag, own, println, eprintln, byStr, isScannableDir, type ParsedArgs } from "../util.js";
import { scanRepo, scanRepoCached, extractionTier } from "../scan.js";
import { buildGraph, reverseDependents } from "../graph.js";
import { enumerateTaint } from "../taint.js";
import { enumerateSinkCandidates } from "../sinks.js";
import { enumerateSensitiveLogCandidates } from "../logs/hygiene.js";
import { auditAgenticWorkflows } from "../actions.js";
import { auditWebConfig } from "../webconfig.js";
import { auditAuthTokens } from "../authtokens.js";
import { auditCloud } from "../cloud.js";
import { buildPruneMatcher } from "../walk.js";
import { auditSecrets } from "../secrets.js";
import { demoteNoise } from "../noise.js";
import { changedFiles } from "../git.js";
import { addProvenance } from "../provenance.js";
import { loadScanCache, saveScanCache } from "../cache.js";
import { orchestrate, toolStatus } from "../tools/run.js";
import { correlate } from "../tools/correlate.js";
import { enrichFindings } from "../tools/scoring.js";
import { generateSbom } from "../tools/sbom.js";
import { ADAPTERS } from "../tools/index.js";
import { writeDossier, loadDossier, mergeDossier, countBySeverity, type Dossier } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Finding, type Manifest } from "../types.js";
import { loadContextDoc } from "../context.js";
import { classifyDependencyReachability } from "../reachability.js";

// Budget presets scale call-graph depth × candidate breadth. `standard` reproduces
// the historical defaults (6 hops / 1000 candidates).
/** What a reader should check before accepting each de-prioritization. Keyed by
 *  `NoiseClass`; an unknown reason falls back to the finding's own message. */
const DOWNGRADE_ADVICE: Record<string, string> = {
  "encrypted-at-rest": "ciphertext by design; the key, not the blob, is the thing to check",
  "test-only-path": "every cited location is a test path — confirm no fixture or test route ships",
  "vendored-artifact": "a vendored or minified build artifact — fix upstream, not here",
  "pattern-declaration": "the cited line declares the pattern rather than performing it — confirm it is not also applied",
  "resource-identifier": "a document/resource id, not a credential — confirm the document's sharing setting",
};

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

  // A path that doesn't exist must NEVER read as a clean audit — a typo'd --repo
  // used to walk zero files and exit 0 with "0 findings", the most dangerous
  // possible silent failure for a security tool.
  if (!isScannableDir(repo)) {
    eprintln(`ultrasec: --repo '${repo}' is not a directory. Aborting — an unscannable path must not report a clean audit.`);
    return 2;
  }

  // Scope knobs (large-repo focus): prune the walk so a huge tree is never fully read.
  const scope = listFlag(args, "scope");
  const include = listFlag(args, "include");
  const exclude = listFlag(args, "exclude");
  const maxFiles = numFlag(args, "max-files");
  const gitignore = flagBool(args, "gitignore");

  // Budget knobs: rank-then-cap taint candidates; explicit flags override the preset.
  // own() guards against a `--budget constructor`-style prototype-member name. An
  // unrecognized name is an ERROR, not a silent fall-back to `standard` — asking for
  // `--budget thorogh` and quietly getting a narrower scan is how coverage is lost
  // without anyone noticing (`logs --budget` has always failed closed this way).
  const budgetName = flagStr(args, "budget");
  if (budgetName !== undefined && !own(BUDGETS, budgetName)) {
    eprintln(`ultrasec: unknown --budget '${budgetName}' (expected ${Object.keys(BUDGETS).join("|")}).`);
    return 2;
  }
  const preset = own(BUDGETS, budgetName ?? "standard") ?? BUDGETS.standard!;
  const maxDepth = numFlag(args, "max-depth") ?? preset.maxDepth;
  const explicitMaxCandidates = numFlag(args, "max-candidates");
  const maxCandidates = explicitMaxCandidates ?? preset.maxCandidates;

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
    const changed = relOut && relOut !== "." && !relOut.startsWith("..") ? changedRaw.filter((f) => f !== relOut && !f.startsWith(relOut + "/")) : changedRaw;
    let targets = changed;
    if (existsSync(join(out, "graph.json"))) {
      try {
        targets = reverseDependents(loadDossier(out).graph, changed, REVDEP_DEPTH);
        // Blast radius: how much else depends on what moved. Risk follows this,
        // not diff size — Heartbleed was two lines. A small change under a large
        // fan-in is the shape that deserves the careful read, and saying so here
        // is the difference between a number and a decision.
        const downstream = targets.length - changed.length;
        const wide = downstream >= 50;
        diffNote =
          `--diff ${diffRef}: ${changed.length} changed → ${targets.length} file(s) incl. reverse-deps ` +
          `(blast radius ${downstream}${wide ? " — WIDE: review removed validation/authz here first, whatever the diff size" : ""})`;
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

  // Live progress. A thorough scan is minutes of silence today — one adapter can
  // spend twenty of them walking git history — and the only way to tell "running"
  // from "hung" was `docker ps`. It goes to STDERR, so stdout (including
  // `--json`) stays byte-identical for anything parsing this command, and it goes
  // through `eprintln` rather than `process.stderr` directly so the MCP server's
  // capture and `--report`'s tee keep working.
  const quiet = flagBool(args, "quiet");
  const step = (msg: string): void => {
    if (!quiet) eprintln(`ultrasec · ${msg}`);
  };
  const secs = (ms: number): string => (ms >= 1000 ? ` in ${Math.round(ms / 1000)}s` : "");

  const scanOpts = { scope: effectiveScope, include, exclude, maxFiles, gitignore };
  const resume = flagBool(args, "resume");
  const cache = resume ? loadScanCache(out) : undefined;
  step(`walking ${repo}${cache ? " (resuming from cache)" : ""}…`);
  const scan = cache ? scanRepoCached(repo, scanOpts, cache) : scanRepo(repo, scanOpts);
  step(`${scan.files.length} file(s) scanned · building the link-graph…`);
  const graph = buildGraph(scan);
  // Logging hygiene (opt-in `--log-hygiene`, CWE-117 + CWE-532): unions LOG_SINKS
  // into the taint sink catalog for this run only — default false keeps the
  // sink-matching step (and therefore every golden/snapshot) byte-identical.
  const logHygieneOn = flagBool(args, "log-hygiene");
  // `--no-env-sources`: drop flows rooted in process.env / os.getenv. Opt-in, so
  // the default candidate set is unchanged (see TaintOptions.excludeEnvSources).
  const excludeEnvSources = flagBool(args, "no-env-sources");
  // `--strict-scope`: drop candidates whose source sits in a DIFFERENT function
  // of the same file. Opt-in for the same reason as above — co-location is weak
  // evidence, not zero evidence (a value can travel through module state).
  const strictScope = flagBool(args, "strict-scope");
  step(`enumerating source→sink taint paths…`);
  const taint = enumerateTaint(scan, graph, { maxDepth, maxCandidates, includeLogSinks: logHygieneOn, excludeEnvSources, strictScope });
  const taintFindings = taint.findings;
  step(`${taintFindings.length} taint candidate(s)`);

  // Orphan-sink recall (opt-in `--sinks`): dangerous sinks the source-gated taint
  // BFS can't connect to a source still warrant a look. Emitted as low-confidence
  // `sast` candidates, de-duped against the taint findings, capped + reported.
  const sinksOn = flagBool(args, "sinks");
  const sinkCand = sinksOn ? enumerateSinkCandidates(scan, taintFindings, { maxCandidates }) : { findings: [] as Finding[], truncated: 0, total: 0 };

  // Sensitive-logging line-content pass (opt-in `--log-hygiene`, CWE-532): every
  // LOG_SINKS call site whose line names a sensitive identifier or contains a
  // literal secret. Capped independently (logging noise floods fast) + reported.
  // Mirrors the EXPLICIT --max-candidates flag (same value taint/--sinks receive)
  // so "Raise --max-candidates" is true here too; absent that flag it keeps its own
  // tighter default (40, see src/logs/hygiene.ts) rather than inheriting the
  // budget-preset value (200/1000/5000), which would silently change today's cap.
  const hygieneCand = logHygieneOn
    ? enumerateSensitiveLogCandidates(scan, { maxCandidates: explicitMaxCandidates })
    : { findings: [] as Finding[], truncated: 0, total: 0 };

  // ONE prune predicate for the whole run. `--gitignore` used to reach only the
  // engine's own walk: the always-on auditors below call `walk(repo)` with no
  // options at all, and the external scanners get the raw repo bind-mounted, so
  // a scan that pruned 1.1 GB of vendored data from its taint graph still
  // shipped 51 findings out of it. Built from the engine's own gitignore
  // primitives so it honours nested `.gitignore` files exactly as the walk does.
  const prune = buildPruneMatcher(repo, { gitignore, exclude });

  step(`agentic-CI, config, auth, cloud and credential detectors…`);
  // Agentic CI: workflows that hand a coding agent the repo's own event data.
  // Always on — it reads only `.github/workflows/*.yml`, costs nothing when there
  // are none, and a repo that ships one of these has a live injection path that
  // no dependency scanner and no taint walk will report.
  const agenticFindings = auditAgenticWorkflows(repo, prune);

  // API/web misconfiguration (CORS, cookie flags, security headers, TLS
  // verification disabled, debug mode, GraphQL introspection). Always on for the
  // same reason as the agentic-CI pass: it reads the source already walked, costs
  // nothing when the shapes are absent, and reports a live class no taint walk or
  // dependency scanner will. Every finding is grounded [file:line], category `config`.
  const webConfigFindings = auditWebConfig(repo, prune);

  // Authentication-token weaknesses (JWT alg/none, key confusion, decode-without-
  // verify, unenforced expiry, hardcoded/weak secrets; OAuth implicit flow, loose
  // redirect_uri, missing state/PKCE; SAML signature off; weak password hashing).
  // Always on, grounded [file:line], category crypto/authz.
  const authTokenFindings = auditAuthTokens(repo, prune);

  // Cloud / K8s / IaC misconfiguration (privileged containers, host namespaces,
  // wildcard IAM, public principals/storage, open ingress, instance-metadata
  // endpoints). Zero-dependency baseline that fires without checkov and folds
  // into it via the correlator when present. Grounded [file:line], category config.
  const cloudFindings = auditCloud(repo, prune);

  // Credentials embedded in connection strings (`scheme://user:secret@host`),
  // including — especially — the ones whose NEIGHBOURING components are
  // templated. `postgresql://$(user):<literal>@$(host)/db` reads as
  // configuration rather than as a credential, which is how it survives review
  // and why entropy/format heuristics skip it; gitleaks and trufflehog both
  // missed exactly that on a public repo. Always on, grounded [file:line].
  const credentialFindings = auditSecrets(repo, prune);

  // External tools: `--tools none`/`--no-tools` skips; `--tools a,b` selects; absent =
  // auto. A SCOPED/diff pass skips them by default (don't re-run Trivy on a drill-down);
  // pass `--tools auto` to force them.
  const scopedScan = !!((effectiveScope && effectiveScope.length) || include?.length || exclude?.length || diffRef);
  const toolsFlag = flagStr(args, "tools");
  const toolsAutoSkipped = scopedScan && toolsFlag === undefined && !flagBool(args, "no-tools");
  const skipTools = flagBool(args, "no-tools") || toolsFlag === "none" || toolsAutoSkipped;
  const which = toolsFlag && toolsFlag !== "auto" && toolsFlag !== "none" ? toolsFlag.split(",").map((s) => s.trim()) : undefined;
  const useDocker = flagBool(args, "docker");
  const offline = flagBool(args, "offline");
  // Produce the CycloneDX SBOM (when `syft` is installed) before running the
  // adapters that can consume it faster than re-walking the tree themselves
  // (grype's `sbom:` mode, package-checker's `--source`) — skipped right along
  // with the adapters when tools aren't going to run this pass.
  const sbomResult = skipTools ? undefined : generateSbom(repo, out);
  if (skipTools) step(`external scanners skipped`);
  const tool = skipTools
    ? { findings: [] as Finding[], toolsRun: [] as string[], results: [] }
    : orchestrate(ADAPTERS, repo, {
        which,
        useDocker,
        offline,
        sbom: sbomResult?.path,
        pruned: prune,
        // Adapters run serially, so this is a running commentary, not a bar.
        // Naming the tool that is currently blocking is the whole point: when a
        // scan sits silent for twenty minutes, the last line printed is what
        // tells you it is trufflehog walking git history rather than a hang.
        onProgress: (e) => {
          const at = `[${e.index}/${e.total}] ${e.tool}`;
          if (!e.result) return step(`${at} …`);
          const mark = !e.result.ran ? "↷" : e.result.ok ? "✓" : "✗";
          step(`${at} ${mark} ${e.result.note}${secs(e.ms ?? 0)}`);
        },
      });

  // Merge taint candidates, orphan-sink candidates, logging-hygiene candidates,
  // and tool findings (ids are disjoint by construction), then correlate the
  // WHOLE set: orchestrate only correlates tool findings among themselves, so
  // without this second (idempotent) pass a scanner finding sitting exactly on a
  // taint/orphan-sink/hygiene node would ship as a duplicate instead of
  // corroborating the candidate.
  const merged = correlate([
    ...taintFindings,
    ...sinkCand.findings,
    ...hygieneCand.findings,
    ...agenticFindings,
    ...webConfigFindings,
    ...authTokenFindings,
    ...cloudFindings,
    ...credentialFindings,
    ...tool.findings,
  ]);

  step(`correlated ${merged.length} finding(s) · de-noising and ranking…`);

  // Noise by construction: the match is REAL, but the code it sits in cannot
  // carry the risk described. Ciphertext in a ciphertext-by-design file
  // (SealedSecrets, SOPS, age…), a taint path whose every node is in the test
  // harness, an entropy hit inside a vendored tool bundle. Measured on a real
  // Next.js monorepo: 46 of 62 taint candidates never left `__tests__`/`*.e2e`.
  //
  // De-prioritized, never dropped, and never auto-adjudicated — the counts land
  // in the manifest below so a suppressed class is still something the run can
  // account for by name.
  const includeTests = flagBool(args, "include-tests");
  const { findings: deNoised, downgraded: noiseDowngrades } = demoteNoise(merged, repo, { includeTests });

  // Which dependency advisories are about code that ships, and which about the
  // toolchain that builds it. Must run BEFORE enrichment: `reachability` damps
  // the composite risk, and a score computed without it would rank a build-only
  // CVE beside a runtime one — which is what put four toolchain advisories in
  // the top severity tier of the first large audit.
  const { findings: reachabilityMarked, toolchain: toolchainCount, sources: reachabilitySources } = classifyDependencyReachability(deNoised, repo);

  // Enrich CVE-bearing findings with EPSS/KEV and compute a risk score on every
  // finding. Network-tolerant (cached feeds); `--no-enrich`/`--offline` skips it.
  const enrich = !(flagBool(args, "no-enrich") || offline);
  const { findings: enriched, note: riskNote } = await enrichFindings(reachabilityMarked, { enabled: enrich, context: loadContextDoc(out) });

  // Provenance (opt-in `--blame`/`--provenance`): deterministic git-blame author/
  // date + CODEOWNERS owner per finding — a triage signal, never a suppression
  // rule. Offline-tolerant: no git / no CODEOWNERS ⇒ findings pass through as-is.
  const blameOn = flagBool(args, "blame") || flagBool(args, "provenance");
  const findings = blameOn ? addProvenance(enriched, repo, { blame: true }) : enriched;

  const languages = [...new Set(scan.files.map((f) => f.lang))].sort();
  // Never hide a capped run as a full one: record candidate + file-walk truncation.
  // Candidate truncation folds the taint, orphan-sink, and logging-hygiene caps together.
  const truncatedCount = taint.truncated + sinkCand.truncated + hygieneCand.truncated;
  const totalCandidates = taint.total + sinkCand.total + hygieneCand.total;
  const truncation =
    truncatedCount > 0 || scan.truncated
      ? { candidates: truncatedCount, total: totalCandidates, ...(scan.truncated ? { files: true as const } : {}) }
      : undefined;
  const recordedScopes = [...(scope ?? []), ...(diffRef ? [`diff:${diffRef}`] : [])].sort(byStr);
  const perToolStatus = tool.results.length ? toolStatus(tool.results) : undefined;
  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo,
    generatedNote: "Taint candidates are deterministic; external-tool results depend on installed scanners.",
    languages,
    toolsRun: tool.toolsRun,
    ...(perToolStatus ? { toolStatus: perToolStatus } : {}),
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    extraction: extractionTier(),
    // Which opt-in passes ran, so a later stage can distinguish "the flag was
    // never passed" from "the flag was passed and the pass found nothing".
    passes: { sinks: sinksOn, logHygiene: logHygieneOn, blame: blameOn, includeTests },
    ...(noiseDowngrades.length ? { downgraded: noiseDowngrades } : {}),
    // What the reachability pass could actually see. A damped score has to be
    // accountable: without this, "toolchain: 0" reads the same whether there
    // were no build-only advisories or no lockfile to tell.
    ...(reachabilitySources.length ? { reachability: { toolchain: toolchainCount, sources: reachabilitySources } } : {}),
    ...(truncation ? { truncation } : {}),
    ...(recordedScopes.length ? { scopes: recordedScopes } : {}),
    ...(sbomResult?.path ? { sbom: "sbom.cdx.json" } : {}),
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
      eprintln(
        `ultrasec: could not merge into the existing dossier at ${out} (${e instanceof Error ? e.message : String(e)}); writing a fresh dossier instead.`,
      );
    }
  }
  step(`writing the dossier to ${out}…`);
  writeDossier(out, final);
  if (cache) saveScanCache(out, cache);

  const fm = final.manifest;
  const fc = fm.counts.bySeverity;
  if (flagBool(args, "json")) {
    const kev = final.findings.filter((f) => f.kev).length;
    println(
      JSON.stringify(
        {
          out,
          counts: fm.counts,
          languages: fm.languages,
          files: scan.files.length,
          toolsRun: fm.toolsRun,
          toolStatus: fm.toolStatus,
          kev,
          risk: riskNote,
          truncation,
          scopes: fm.scopes,
          sbom: fm.sbom,
          diff: diffNote,
          sinks: sinksOn ? sinkCand.findings.length : undefined,
          logHygiene: logHygieneOn ? hygieneCand.findings.length : undefined,
          downgraded: fm.downgraded,
          merged: mergedNote.trim() || undefined,
        },
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
  if (sbomResult) println(`  sbom: ${sbomResult.note}`);
  println(
    `  candidate findings: ${fm.counts.findings}  (crit ${fc.critical} · high ${fc.high} · med ${fc.medium} · low ${fc.low})  ·  ${taintFindings.length} taint${sinksOn ? ` + ${sinkCand.findings.length} sink` : ""}${logHygieneOn ? ` + ${hygieneCand.findings.length} log-hygiene` : ""} + ${tool.findings.length} tool this pass`,
  );
  println(`  ${riskNote}`);
  if (fm.reachability) {
    const { toolchain, sources } = fm.reachability;
    println(
      `  reachability: ${toolchain} dependency advisory(ies) marked build-only (from ${sources.join(", ")})` +
        `${sources.includes("package-lock.json") || sources.includes("npm-shrinkwrap.json") ? "" : " — direct devDependencies only; a transitive dev-only package stays unmarked"}`,
    );
  }
  // One line per suppressed class, each naming what to check before believing
  // it — a demotion the reader cannot interrogate is a silent filter.
  for (const d of fm.downgraded ?? []) {
    println(`  ${d.count} finding(s) de-prioritized — ${d.reason}: ${DOWNGRADE_ADVICE[d.reason] ?? "see the finding's message for what was checked"}`);
  }
  if (truncation?.candidates) {
    println(
      `  ⚠️  showing top ${maxCandidates} of ${truncation.total} candidates — ${truncation.candidates} not shown. Raise --max-candidates or narrow --scope.`,
    );
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
