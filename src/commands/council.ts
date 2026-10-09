import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { formatDropped } from "../apply-parse.js";
import { loadContextDoc } from "../context.js";
import { headCommit } from "../git.js";
import { loadDossier, type Dossier } from "../store.js";
import { persistFindings, readApply } from "../stage.js";
import type { Finding } from "../types.js";
import { eprintln, flagBool, flagStr, numFlag, println, type ParsedArgs, linesCapped } from "../util.js";
import { applyCouncil, mergeDecisions, parseDecisions } from "../council/apply.js";
import { briefName, buildDevilList, LANGS, PHASES, renderBrief, type Lang, type Phase } from "../council/brief.js";
import { indexTree, parseReport, type Claim } from "../council/claims.js";
import { consolidate, type CouncilTodo } from "../council/consolidate.js";
import {
  BRIEF_MD,
  councilDir,
  loadLedger,
  newLedger,
  renderCouncilMd,
  reviewerDir,
  saveLedger,
  snapshotDir,
  TODO,
  upsertReviewer,
  usageLine,
  type Ledger,
  type ReviewerRecord,
} from "../council/ledger.js";
import {
  defaultConfigPath,
  loadRegistry,
  onPath,
  parseFocus,
  parseModelList,
  reviewersFrom,
  usageExposed,
  type ModelSpec,
  type Reviewer,
  type ReviewerRegistry,
} from "../council/reviewers.js";
import { defaultSpawner, runReviewer, type CouncilSpawner, type RunnerContext } from "../council/runner.js";
import { ensureSnapshot, snapshotFiles } from "../council/snapshot.js";
import { compilePlaceholderPatterns } from "../placeholders.js";

// `ultrasec council --run <dir> [--repo .] [--phase blind|devil] --models "<reviewer>:<model>,…"
//     [--focus "name=area;…"] [--fallback "<reviewer>:<model>,…"] [--timeout-min 60] [--max-cost <usd>]
//     [--lang en|fr] [--reviewer-config <file.json>] [--placeholder-pattern <regex>]… [--json]`
// `ultrasec council --run <dir> --parse`             re-parse reviewer outputs → COUNCIL.todo.json/COUNCIL.md
// `ultrasec council --run <dir> --resume <reviewer>` one-turn finalisation of a cut reviewer
// `ultrasec council --run <dir> --apply <decisions>` fold the orchestrator's decisions
//
// A second opinion from other model families, made a command instead of a
// paragraph of advice. On one web-application audit, three external reviewers
// produced the run's only HIGH that neither the engine nor the first manual
// pass had seen — and four confident claims that were false. Both outcomes
// shape this: reviewers propose on a snapshot, the orchestrator verifies, and
// nothing enters the run except through the citation gate.
//
// A reviewer is any agent CLI described as data (`council/reviewers.ts`):
// built-in presets, or entries of a `--reviewer-config` file.
//
// Without `--models` it prints the plan and calls NOTHING: which reviewer CLIs
// are on PATH (a filesystem probe, not a spawn) and the commands it would run.

export interface CouncilDeps {
  spawner?: CouncilSpawner;
  /** Test seam: replace a reviewer's binary with an argv prefix (a fake CLI). */
  commands?: Record<string, string[]>;
  baseEnv?: NodeJS.ProcessEnv;
}

const DEFAULT_TIMEOUT_MIN = 60;
const DEFAULT_MAX_TURNS = 100;

export function runCouncil(args: ParsedArgs): Promise<number> {
  return runCouncilWith(args, {});
}

/** Every string value of a repeatable flag, verbatim (no comma split: a regex may hold one). */
function rawFlagValues(args: ParsedArgs, name: string): string[] {
  const v = args.flags[name];
  if (v === undefined) return [];
  return (Array.isArray(v) ? v : [v]).filter((x): x is string => typeof x === "string");
}

function fail(msg: string): number {
  eprintln(`ultrasec council: ${msg}`);
  return 2;
}

function tryDossier(run: string): Dossier | undefined {
  try {
    return loadDossier(run);
  } catch {
    return undefined;
  }
}

/**
 * The snapshot is a full copy of the source, and it must not outlive the
 * command that needed it: the run directory is what gets shared, and a later
 * `scan` of a repo whose run dir is not named `.ultrasec` would index the copy
 * and report every bug twice. It is recreated from the recorded commit on
 * demand — `git archive` takes seconds — so nothing is lost by dropping it.
 */
function dropSnapshot(run: string): void {
  rmSync(snapshotDir(run), { recursive: true, force: true });
}

/** Re-parse every recorded report against the snapshot and rewrite the worklist. */
export function reparse(
  run: string,
  repo: string,
  ledger: Ledger,
  findings: readonly Finding[],
  placeholders: readonly RegExp[] = [],
): { todo: CouncilTodo; claims: Claim[] } {
  const snap = ensureSnapshot(repo, snapshotDir(run), ledger.commit, ledger.commit);
  const idx = indexTree(snap.dir, snapshotFiles(snap.dir));
  const claims: Claim[] = [];
  for (const r of ledger.reviewers) {
    if (!r.report || !existsSync(join(run, r.report))) continue;
    claims.push(...parseReport(readFileSync(join(run, r.report), "utf8"), { reviewer: r.name, phase: r.phase }, idx, { placeholders }));
  }
  const todo = consolidate(claims, findings, ledger.commit);
  writeFileSync(join(councilDir(run), TODO), JSON.stringify(todo, null, 2));
  writeFileSync(join(councilDir(run), BRIEF_MD), renderCouncilMd(run, ledger, todo));
  return { todo, claims };
}

export async function runCouncilWith(args: ParsedArgs, deps: CouncilDeps): Promise<number> {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const dossier = tryDossier(run);
  let ledger: Ledger | undefined;
  try {
    ledger = loadLedger(run);
  } catch (e) {
    return fail(`unreadable ${join(councilDir(run), "COUNCIL.json")}: ${(e as Error).message}`);
  }
  const repo = resolve(flagStr(args, "repo") ?? dossier?.manifest.repo ?? ledger?.repo ?? ".");

  // `--resume` is a boolean flag elsewhere (`scan --resume`), so the parser
  // leaves the reviewer name as a positional; `--resume=<name>` works too.
  const resumeName = flagStr(args, "resume") ?? (flagBool(args, "resume") ? args._[1] : undefined);
  const applyPath = flagStr(args, "apply");
  const modelsRaw = flagStr(args, "models");
  const parseOnly = flagBool(args, "parse");
  const modes = [applyPath, parseOnly || undefined, flagBool(args, "resume") || resumeName ? true : undefined, modelsRaw].filter((m) => m !== undefined);
  if (modes.length > 1) return fail("--models, --parse, --resume and --apply are separate steps — pass one.");
  if (flagBool(args, "resume") && !resumeName) return fail("--resume needs a reviewer name (e.g. `--resume <reviewer>`).");

  // Reviewers and placeholder shapes: presets, then the user's config (never
  // the audited repo's — see `defaultConfigPath`), then the flags.
  let registry: ReviewerRegistry;
  try {
    const extra = compilePlaceholderPatterns(rawFlagValues(args, "placeholder-pattern"), "--placeholder-pattern");
    const configPath = flagStr(args, "reviewer-config");
    registry = loadRegistry({ ...(configPath ? { configPath } : {}), env: deps.baseEnv ?? process.env, extraPlaceholders: extra });
  } catch (e) {
    return fail((e as Error).message);
  }
  const placeholders = registry.placeholderPatterns;

  const lang = (flagStr(args, "lang") ?? ledger?.lang ?? "en") as Lang;
  if (!LANGS.includes(lang)) return fail(`unknown --lang "${lang}" (expected ${LANGS.join("|")}).`);
  const phaseRaw = flagStr(args, "phase");
  if (phaseRaw !== undefined && !(PHASES as readonly string[]).includes(phaseRaw)) return fail(`unknown --phase "${phaseRaw}" (expected ${PHASES.join("|")}).`);
  const timeoutMin = numFlag(args, "timeout-min") ?? DEFAULT_TIMEOUT_MIN;
  if (!(timeoutMin > 0)) return fail("--timeout-min must be a positive number of minutes.");
  const maxCost = numFlag(args, "max-cost");
  if (flagStr(args, "max-cost") !== undefined && !(maxCost !== undefined && maxCost >= 0)) return fail("--max-cost must be a number of dollars ≥ 0.");
  let fallbacks: ModelSpec[] = [];
  try {
    const fb = flagStr(args, "fallback");
    if (fb) fallbacks = parseModelList(fb, "--fallback", registry);
  } catch (e) {
    return fail((e as Error).message);
  }
  const json = flagBool(args, "json");

  if (applyPath) return applyMode(run, repo, dossier, ledger, applyPath, json, flagBool(args, "strict"));
  if (parseOnly) {
    if (!ledger) return fail(`no council at ${councilDir(run)} — run \`council --models …\` first.`);
    try {
      const { todo } = reparse(run, repo, ledger, dossier?.findings ?? [], placeholders);
      return printParse(run, ledger, todo, json);
    } catch (e) {
      return fail((e as Error).message);
    } finally {
      dropSnapshot(run);
    }
  }

  const ctxBase = {
    run,
    lang,
    timeoutMs: timeoutMin * 60_000,
    ...(maxCost !== undefined ? { maxCost } : {}),
    maxTurns: DEFAULT_MAX_TURNS,
    fallbacks,
    registry,
    placeholders,
    spawner: deps.spawner ?? defaultSpawner,
    ...(deps.commands ? { commands: deps.commands } : {}),
    ...(deps.baseEnv ? { baseEnv: deps.baseEnv } : {}),
  };

  if (resumeName) {
    if (!ledger) return fail(`no council at ${councilDir(run)} — nothing to resume.`);
    const candidates = ledger.reviewers.filter((r) => r.name === resumeName && (!phaseRaw || r.phase === phaseRaw));
    const rec = candidates.find((r) => r.phase === "devil") ?? candidates[0];
    if (!rec)
      return fail(
        `no reviewer "${resumeName}"${phaseRaw ? ` in phase ${phaseRaw}` : ""} (known: ${[...new Set(ledger.reviewers.map((r) => r.name))].join(", ") || "none"}).`,
      );
    if (!registry.specs.has(rec.cli))
      return fail(
        `reviewer "${rec.name}" ran as "${rec.cli}", which is neither a preset nor in the reviewer config — pass the --reviewer-config that defined it.`,
      );
    if (rec.resetAt) println(`  ⏳ ${rec.name}: the provider said the quota resets at ${rec.resetAt} — resuming anyway.`);
    try {
      return await resumeMode(run, repo, ledger, rec, ctxBase, dossier, json);
    } finally {
      dropSnapshot(run);
    }
  }

  if (!modelsRaw) return printPlan(run, repo, json, registry, deps.baseEnv);
  try {
    return await modelsMode(run, repo, ledger, modelsRaw, flagStr(args, "focus"), (phaseRaw ?? "blind") as Phase, lang, ctxBase, dossier, json);
  } finally {
    dropSnapshot(run);
  }
}

type CtxBase = Omit<RunnerContext, "snapshot" | "phase">;

async function resumeMode(
  run: string,
  repo: string,
  ledger: Ledger,
  rec: ReviewerRecord,
  ctxBase: CtxBase,
  dossier: Dossier | undefined,
  json: boolean,
): Promise<number> {
  let snap: ReturnType<typeof ensureSnapshot>;
  try {
    snap = ensureSnapshot(repo, snapshotDir(run), ledger.commit, ledger.commit);
  } catch (e) {
    return fail((e as Error).message);
  }
  const reviewer: Reviewer = { name: rec.name, cli: rec.cli, model: rec.model, ...(rec.focus ? { focus: rec.focus } : {}) };
  // The session was told to follow its brief; give it back the same one.
  const kept = join(reviewerDir(run, rec.phase, rec.name), "brief.md");
  if (existsSync(kept)) copyFileSync(kept, join(snap.dir, briefName(rec.phase, rec.name)));
  else writeBrief(run, snap.dir, rec.phase, reviewer, ctxBase.lang, ledger, dossier);
  const ctx: RunnerContext = { ...ctxBase, snapshot: snap.dir, phase: rec.phase };
  const next = await runReviewer(ctx, reviewer, rec);
  upsertReviewer(ledger, next);
  saveLedger(run, ledger);
  const { todo } = reparse(run, repo, ledger, dossier?.findings ?? [], ctxBase.placeholders);
  if (json) println(JSON.stringify({ reviewer: next, candidates: todo.candidates.length }, null, 2));
  else {
    println(`ultrasec council --resume ${rec.name} (${rec.phase}) → ${next.status}`);
    printReviewer(run, next);
  }
  return next.status === "ok" ? 0 : 1;
}

async function modelsMode(
  run: string,
  repo: string,
  prior: Ledger | undefined,
  modelsRaw: string,
  focusRaw: string | undefined,
  phase: Phase,
  lang: Lang,
  ctxBase: CtxBase,
  dossier: Dossier | undefined,
  json: boolean,
): Promise<number> {
  let ledger = prior;
  let reviewers: Reviewer[];
  try {
    reviewers = reviewersFrom(parseModelList(modelsRaw, "--models", ctxBase.registry), parseFocus(focusRaw));
  } catch (e) {
    return fail((e as Error).message);
  }
  if (phase === "devil" && !dossier) return fail(`--phase devil attacks the run's findings, and ${run} has no dossier — scan and verify first.`);

  let snap: ReturnType<typeof ensureSnapshot>;
  try {
    snap = ensureSnapshot(repo, snapshotDir(run), ledger?.commit);
  } catch (e) {
    return fail((e as Error).message);
  }
  ledger ??= newLedger(repo, snap.commit, lang);
  ledger.commit = snap.commit;
  ledger.repo = repo;
  ledger.lang = lang;

  for (const r of reviewers) writeBrief(run, snap.dir, phase, r, lang, ledger, dossier);
  const ctx: RunnerContext = { ...ctxBase, snapshot: snap.dir, phase };
  if (!json)
    println(`ultrasec council --phase ${phase} → ${councilDir(run)} (${reviewers.length} reviewer(s) in parallel on snapshot ${snap.commit.slice(0, 12)})`);
  const records = await Promise.all(reviewers.map((r) => runReviewer(ctx, r)));
  for (const rec of records) upsertReviewer(ledger, rec);
  saveLedger(run, ledger);
  const { todo } = reparse(run, repo, ledger, dossier?.findings ?? [], ctxBase.placeholders);

  if (json)
    println(
      JSON.stringify(
        { phase, reviewers: records, candidates: todo.candidates.length, corroborations: todo.corroborations.length, contested: todo.contested.length },
        null,
        2,
      ),
    );
  else {
    for (const rec of records) printReviewer(run, rec);
    printTodoSummary(run, todo);
  }
  return records.every((r) => r.status === "ok") ? 0 : 1;
}

/** The brief goes into the snapshot (for the reviewer) and beside its logs (for the record, and for a later resume). */
function writeBrief(run: string, snapshot: string, phase: Phase, r: Reviewer, lang: Lang, ledger: Ledger, dossier: Dossier | undefined): void {
  const devil =
    phase === "devil" && dossier
      ? buildDevilList(
          dossier.findings,
          ledger.decisions.rejected.map((d) => ({ id: d.candidate, title: d.title, reason: d.reason ?? "" })),
        )
      : undefined;
  const ctx = loadContextDoc(run);
  const body = renderBrief({
    lang,
    phase,
    commit: ledger.commit,
    ...(r.focus ? { focus: r.focus } : {}),
    ...(ctx ? { context: ctx } : {}),
    ...(devil ? { devil } : {}),
  });
  writeFileSync(join(snapshot, briefName(phase, r.name)), body);
  const dir = reviewerDir(run, phase, r.name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "brief.md"), body);
}

function printReviewer(run: string, r: ReviewerRecord): void {
  const mark = r.status === "ok" ? "✓" : "✗";
  println(
    `  ${mark} ${r.name.padEnd(10)} ${`${r.cli}:${r.model || "(default)"}`.padEnd(36)} ${r.status.padEnd(13)} ${usageLine(r.usage)}${r.report ? ` · ${r.report}` : ""}`,
  );
  if (r.attempts.length > 1)
    println(`      attempts: ${r.attempts.map((a) => `${a.resume ? "resume " : ""}${a.cli}:${a.model || "(default)"} → ${a.status}`).join(" · ")}`);
  if (r.status !== "ok") {
    const why = r.attempts.at(-1)?.failure?.message;
    if (why) println(`      ${why}`);
    if (r.resetAt) println(`      quota resets at ${r.resetAt} — then: ultrasec council --run ${run} --resume ${r.name} --phase ${r.phase}`);
    else if (r.session) println(`      resume later: ultrasec council --run ${run} --resume ${r.name} --phase ${r.phase} [--fallback "${r.cli}:<model>"]`);
  }
}

function printTodoSummary(run: string, todo: CouncilTodo): void {
  const multi = todo.candidates.filter((c) => c.corroboration > 1).length;
  println(
    `  candidates: ${todo.candidates.length} (${multi} raised by ≥2 reviewers) · corroborations of existing findings: ${todo.corroborations.length} · contested: ${todo.contested.length}`,
  );
  println(`  worklist: ${join(councilDir(run), BRIEF_MD)} · ${join(councilDir(run), TODO)}`);
  println(`  next: open every cited line, reproduce what you can, then write [{id, decision: accept|reject, reason}] and run`);
  println(`        ultrasec council --run ${run} --apply <decisions.json>   (contested ids are a re-verify worklist, never applied)`);
}

function printParse(run: string, ledger: Ledger, todo: CouncilTodo, json: boolean): number {
  if (json) {
    println(JSON.stringify(todo, null, 2));
    return 0;
  }
  println(`ultrasec council --parse → ${join(councilDir(run), TODO)} (${ledger.reviewers.filter((r) => r.report).length} report(s))`);
  printTodoSummary(run, todo);
  return 0;
}

function printPlan(run: string, repo: string, json: boolean, registry: ReviewerRegistry, baseEnv?: NodeJS.ProcessEnv): number {
  const path = (baseEnv ?? process.env).PATH ?? "";
  const clis = [...registry.specs.values()].map((spec) => {
    const at = onPath(spec.bin, path);
    return {
      reviewer: spec.name,
      bin: spec.bin,
      source: registry.fromConfig.has(spec.name) ? "config" : "preset",
      installed: !!at,
      ...(at ? { path: at } : {}),
      usage: usageExposed(spec),
      resume: !!spec.resumeArgs,
      readOnly: spec.readOnly,
    };
  });
  const commit = headCommit(repo);
  const config = registry.source ?? null;
  if (json) {
    println(
      JSON.stringify({ run, repo, commit, externalCalls: 0, config, configDefault: defaultConfigPath(baseEnv ?? process.env), reviewers: clis }, null, 2),
    );
    return 0;
  }
  println(`ultrasec council → ${councilDir(run)} (no --models: plan only, ZERO external calls)`);
  println(`  repo: ${repo} @ ${commit ? commit.slice(0, 12) : "not a git checkout — council needs a commit to snapshot"}`);
  println(
    `  reviewer config: ${config ?? `none (presets only; add reviewers in ${defaultConfigPath(baseEnv ?? process.env)} or --reviewer-config <file.json>)`}`,
  );
  println(`  reviewers:`);
  const w = Math.max(9, ...clis.map((c) => c.reviewer.length + 1));
  for (const c of clis)
    println(
      `    ${c.installed ? "✓" : "✗"} ${c.reviewer.padEnd(w)} ${c.installed ? c.path : `${c.bin} not found`}${c.source === "config" ? "  (config)" : ""}${c.usage ? "" : "  (usage not exposed)"} — read-only: ${c.readOnly}`,
    );
  const have = clis.filter((c) => c.installed).map((c) => `${c.reviewer}:<provider>/<model>`);
  println(`  blind pass:   ultrasec council --run ${run} --models "${have.length ? have.join(",") : "<reviewer>:<provider>/<model>,…"}"`);
  println(`  then:         ultrasec council --run ${run} --apply <decisions.json>   ·   --phase devil after verify`);
  println(`  each reviewer works on a \`git archive HEAD\` snapshot with an emptied environment; nothing enters the run unverified.`);
  return 0;
}

function applyMode(
  run: string,
  repo: string,
  dossier: Dossier | undefined,
  ledger: Ledger | undefined,
  applyPath: string,
  json: boolean,
  strict: boolean,
): number {
  if (!dossier) return fail(`--apply folds into the run's findings, and ${run} has no dossier.`);
  if (!ledger) return fail(`no council at ${councilDir(run)} — nothing to apply.`);
  let todo: CouncilTodo;
  try {
    todo = JSON.parse(readFileSync(join(councilDir(run), TODO), "utf8")) as CouncilTodo;
  } catch (e) {
    return fail(`cannot read ${join(councilDir(run), TODO)} — run \`council --parse\` first (${(e as Error).message}).`);
  }
  let parsed: ReturnType<typeof parseDecisions>;
  try {
    parsed = readApply(applyPath, /(council|decision).*\.json$/i, parseDecisions);
  } catch (e) {
    return fail(`cannot read decisions at ${(e as Error).message}`);
  }
  const res = applyCouncil(dossier, todo, parsed.rows, repo, { context: loadContextDoc(run) });
  persistFindings(run, dossier, res.findings);
  ledger.decisions = mergeDecisions(ledger.decisions, { accepted: res.accepted, rejected: res.rejected });
  saveLedger(run, ledger);
  writeFileSync(join(councilDir(run), BRIEF_MD), renderCouncilMd(run, ledger, todo));

  const refusals = parsed.dropped.length + res.refused.length + res.rejected.filter((r) => r.by === "citation-gate").length;
  if (json) {
    println(
      JSON.stringify(
        {
          accepted: res.accepted,
          rejected: res.rejected,
          refused: res.refused,
          dropped: parsed.dropped,
          ingested: res.ingested,
          folded: res.folded,
          contested: todo.contested.length,
        },
        null,
        2,
      ),
    );
    return strict && refusals > 0 ? 1 : 0;
  }
  println(`ultrasec council --apply → updated ${run}/findings.json`);
  println(
    `  accepted ${res.accepted.length} (ingested ${res.ingested} new ultrasec-ai candidate(s), folded ${res.folded}) · rejected ${res.rejected.length} · refused ${res.refused.length} · dropped ${parsed.dropped.length}`,
  );
  // Each list capped; `--json` carries every row.
  for (const line of linesCapped(res.accepted.map((a) => `  ✓ ${a.candidate} → ${a.findingId ?? "folded into an existing finding"} — ${a.title}`)))
    println(line);
  for (const line of linesCapped(
    res.rejected.map((r) => `  ✗ ${r.candidate} ${r.by === "citation-gate" ? "refused by the citation gate" : "rejected"}: ${r.reason}`),
  ))
    println(line);
  for (const line of linesCapped(res.refused.map((r) => `  ✗ ${r.id}: ${r.reason}`))) println(line);
  for (const line of linesCapped(formatDropped(parsed.dropped))) println(line);
  if (todo.contested.length)
    println(`  ${todo.contested.length} contested finding(s) stay a worklist (COUNCIL.md) — re-verify those findings; nothing was changed for them.`);
  if (res.ingested) println(`  next: \`ultrasec verify --run ${run}\` — accepted candidates are open, and are adjudicated like any other.`);
  return strict && refusals > 0 ? 1 : 0;
}
