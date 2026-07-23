import { resolve, join, dirname, extname, sep } from "node:path";
import { existsSync, statSync, readdirSync, mkdirSync, writeFileSync, openSync, readSync, closeSync } from "node:fs";
import { flagStr, flagBool, numFlag, println, eprintln, byStr, type ParsedArgs } from "../util.js";
import { analyzeLogs, type AnalyzeOptions } from "../logs/analyze.js";
import type { LogFormat } from "../logs/detect.js";
import { buildGraph } from "../graph.js";
import { writeDossier, countBySeverity } from "../store.js";
import { VERSION, SCHEMA_VERSION, type Manifest } from "../types.js";

// `ultrasec logs <path…> [--out DIR] [--format F] [--budget B] [--max-lines N]
//   [--no-redact] [--json]`
//
// A DEFENSIVE, blue-team sibling of `scan`: ingest existing log files, run
// deterministic attack-signature detection (SQLi/XSS/traversal/cmdinj/probe-path
// + known scanner user-agents), and write a STANDARD dossier — same
// findings.json/manifest.json/graph.json/DOSSIER.md shape as every other
// command — whose findings cite `[logfile:line]`. That's what lets the
// existing grounding gate (`check`), `verify`, and `render` work UNCHANGED: a
// log finding is just a finding whose "source code" happens to be a log line.
// Log findings never enter the code-scan pipeline (own dossier, own --out;
// never folds into a `scan` run) — buildGraph({repo: base, files: []}) gives
// an intentionally empty graph, same pattern as `import`.
export async function runLogs(args: ParsedArgs): Promise<number> {
  const inputs = args._.slice(1);
  if (!inputs.length) {
    eprintln("ultrasec logs: need at least one log file or directory — `ultrasec logs <path…>`.");
    return 2;
  }

  let files: string[];
  try {
    files = expandInputs(inputs);
  } catch (e) {
    eprintln(`ultrasec logs: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  if (!files.length) {
    eprintln("ultrasec logs: no log-looking files found in the given path(s) (expected *.log/*.jsonl/*.txt, or text files with no extension).");
    return 2;
  }

  let base: string;
  try {
    base = computeBase(files);
  } catch (e) {
    eprintln(`ultrasec logs: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }

  const out = resolve(flagStr(args, "out") ?? ".ultrasec-logs");
  const budget = (flagStr(args, "budget") ?? "standard") as AnalyzeOptions["budget"];
  if (!["quick", "standard", "thorough"].includes(budget)) {
    eprintln(`ultrasec logs: unknown --budget '${budget}' (expected quick|standard|thorough).`);
    return 2;
  }
  const format = flagStr(args, "format") as LogFormat | undefined;
  const maxLines = numFlag(args, "max-lines");
  const redactOn = !flagBool(args, "no-redact");

  const { findings, stats, truncation } = await analyzeLogs(files, { budget, format, maxLines, redact: redactOn, base });
  findings.sort((a, b) => byStr(a.id, b.id));

  const graph = buildGraph({ repo: base, files: [] });

  // See analyze.ts's per-family cap: overflow there is genuinely analogous to
  // `scan`'s taint-candidate cap (real candidates dropped by a hard limit), so
  // it's surfaced through the SAME manifest.truncation field/shape scan uses —
  // one coverage-capped banner in DOSSIER.md, not a bespoke logs-only field.
  // A budget stop (fewer LINES read than exist) is a different kind of
  // truncation — reported via `truncation[]`/stdout/exit code instead, since
  // the shared DOSSIER.md copy for `truncation.files` names scan-only flags
  // (--max-files/--scope) that don't apply here.
  const familyOverflow = truncation
    .map((t) => /^family \S+: (\d+) further hit/.exec(t))
    .filter((m): m is RegExpExecArray => m !== null)
    .reduce((sum, m) => sum + Number(m[1]), 0);
  const signatureFindings = findings.filter((f) => f.sink?.kind && f.sink.kind !== "scanner-ua").length;

  const manifest: Manifest = {
    version: VERSION,
    schemaVersion: SCHEMA_VERSION,
    repo: base,
    generatedNote:
      "Log-forensics run: deterministic attack-signature + scanner-UA detection over ingested log files — candidates only, YOU judge each (see the log-forensics playbook). No dataflow reasoning, no behavioral aggregation (yet).",
    languages: [],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(familyOverflow > 0 ? { truncation: { candidates: familyOverflow, total: familyOverflow + signatureFindings } } : {}),
  };

  writeDossier(out, { manifest, findings, graph });
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "LOGSTATS.json"), JSON.stringify(stats, null, 2));

  if (flagBool(args, "json")) {
    println(JSON.stringify({ out, base, files: stats.files, findings: findings.length, stats, truncation }, null, 2));
    return 0;
  }

  const byFamily = new Map<string, number>();
  for (const f of findings) {
    const fam = f.sink?.kind ?? "other";
    byFamily.set(fam, (byFamily.get(fam) ?? 0) + 1);
  }

  println(`ultrasec logs → ${out}`);
  println(`  base: ${base}`);
  println(
    `  ${stats.files.length} file(s), ${stats.totalLines.toLocaleString("en-US")} line(s): ${stats.files.map((f) => `${f.path} (${f.format}, ${f.lines})`).join(", ")}`,
  );
  println(
    `  findings: ${findings.length}${
      byFamily.size
        ? " — " +
          [...byFamily.entries()]
            .sort((a, b) => byStr(a[0], b[0]))
            .map(([k, v]) => `${k}: ${v}`)
            .join(", ")
        : ""
    }`,
  );
  if (stats.topIps.length)
    println(
      `  top IPs: ${stats.topIps
        .slice(0, 3)
        .map((i) => `${i.ip} (${i.count})`)
        .join(", ")}`,
    );
  if (truncation.length) {
    println(`  ⚠️ coverage notes (${truncation.length}):`);
    for (const t of truncation.slice(0, 10)) println(`    - ${t}`);
    if (truncation.length > 10) println(`    - …and ${truncation.length - 10} more`);
  }
  println(`  next: read ${join(out, "DOSSIER.md")}; triage with the log-forensics playbook; verify with \`ultrasec verify --run ${out}\`.`);
  return 0;
}

const LOG_EXTENSIONS = new Set([".log", ".jsonl", ".txt"]);

/** Crude binary sniff over the first KB: a NUL byte means "not text". */
function looksLikeText(path: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return false;
  }
  try {
    const buf = Buffer.alloc(1024);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return !buf.subarray(0, n).includes(0);
  } catch {
    return false;
  } finally {
    closeSync(fd);
  }
}

/** Resolve CLI positionals (files and/or directories) into a sorted, deduped
 *  list of absolute log FILE paths. Directories are expanded non-recursively —
 *  only the log-looking files directly inside them. */
export function expandInputs(inputs: string[]): string[] {
  const out = new Set<string>();
  for (const raw of inputs) {
    const p = resolve(raw);
    if (!existsSync(p)) throw new Error(`path not found: ${raw}`);
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const entry of readdirSync(p).sort(byStr)) {
        const full = join(p, entry);
        let est: ReturnType<typeof statSync>;
        try {
          est = statSync(full);
        } catch {
          continue;
        }
        if (!est.isFile()) continue;
        const ext = extname(entry).toLowerCase();
        if (LOG_EXTENSIONS.has(ext) || (ext === "" && looksLikeText(full))) out.add(full);
      }
    } else if (st.isFile()) {
      out.add(p);
    } else {
      throw new Error(`not a file or directory: ${raw}`);
    }
  }
  return [...out].sort(byStr);
}

/** The directory every resolved log file's dirname shares. */
function strictCommonAncestor(dirs: string[]): string | undefined {
  if (!dirs.length) return undefined;
  let common = dirs[0]!.split(sep);
  for (const d of dirs.slice(1)) {
    const parts = d.split(sep);
    let i = 0;
    while (i < common.length && i < parts.length && common[i] === parts[i]) i++;
    common = common.slice(0, i);
    if (!common.length) return undefined;
  }
  const joined = common.join(sep);
  return joined === "" ? sep : joined;
}

/**
 * `manifest.repo` for a logs run — every finding's `sink.file` is stored
 * relative to this. Prefers `cwd` (the conventional ultrasec default, and the
 * nicer/shorter citation base) whenever cwd is genuinely an ancestor of every
 * input file — never otherwise, so a citation can never need to escape the
 * base (`insideRepo()` would then skip grading it — an ungroundable citation
 * by omission). Falls back to the true common ancestor directory; throws
 * (caller exits 2) only if the inputs share no ancestor at all.
 */
export function computeBase(absFiles: string[]): string {
  const cwd = resolve(process.cwd());
  if (absFiles.every((f) => f.startsWith(cwd + sep))) return cwd;
  const common = strictCommonAncestor(absFiles.map((f) => dirname(f)));
  if (!common) throw new Error("input log paths share no common ancestor directory — pass paths under one common root.");
  return common;
}
