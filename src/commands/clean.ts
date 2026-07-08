import { execFileSync } from "node:child_process";
import { existsSync, rmSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { flagStr, flagBool, println, eprintln, type ParsedArgs } from "../util.js";
import { ADAPTERS } from "../tools/index.js";

// `ultrasec clean` — tidy up everything ultrasec creates, easily, from the
// script: the intermediate scan artifacts, and (with --docker) the scanner images
// it pulls, the toolbox image, and the trivy cache volume. So nothing lingers when
// you're done. By DEFAULT the rendered deliverables (REPORT/SUMMARY/index.html +
// findings.json) are PRESERVED — clean removes only the scratch files. --all wipes
// the whole run dir; --keep-output keeps everything; --dry-run shows what would go.

const TOOLBOX_IMAGE = "ultrasec-toolbox";
const VOLUME_NAME_FILTER = "trivy-cache"; // substring match: ultrasec_trivy-cache, ultrasec-trivy-cache…

// The human-facing outputs a user actually wants to keep after an audit. Everything
// else in the run dir is an intermediate ultrasec can regenerate from a re-scan.
const DELIVERABLES = new Set(["SUMMARY.md", "REPORT.md", "index.html", "findings.json"]);

/** The Docker artifacts ultrasec is responsible for (pinned scanner images + toolbox). */
export function dockerImages(): string[] {
  return [...new Set(ADAPTERS.map((a) => a.dockerImage).filter((x): x is string => Boolean(x))), TOOLBOX_IMAGE];
}

function dockerAvailable(): boolean {
  try {
    execFileSync("docker", ["--version"], { stdio: "ignore", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function docker(args: string[]): { ok: boolean; out: string } {
  try {
    const out = execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 60000 });
    return { ok: true, out };
  } catch {
    return { ok: false, out: "" };
  }
}

export function runClean(args: ParsedArgs): number {
  const run = resolve(flagStr(args, "run") ?? ".ultrasec");
  const dry = flagBool(args, "dry-run");
  const withDocker = flagBool(args, "docker");
  const keepOutput = flagBool(args, "keep-output");
  const all = flagBool(args, "all");
  const removed: string[] = [];
  const kept: string[] = [];

  // 1. The generated audit dossier. Default: remove the intermediate scratch files
  //    but PRESERVE the rendered deliverables so a naive cleanup never destroys the
  //    report a user just produced. --all wipes everything; --keep-output keeps all.
  if (!keepOutput && existsSync(run)) {
    if (all) {
      if (!dry) rmSync(run, { recursive: true, force: true });
      removed.push(`output  ${run}`);
    } else {
      let preservedAny = false;
      for (const entry of readdirSync(run)) {
        if (DELIVERABLES.has(entry)) {
          preservedAny = true;
          kept.push(`deliverable  ${join(run, entry)}`);
          continue;
        }
        if (!dry) rmSync(join(run, entry), { recursive: true, force: true });
        removed.push(`intermediate  ${join(run, entry)}`);
      }
      // A run that was never rendered has nothing worth keeping — prune the dir.
      if (!preservedAny) {
        if (!dry) rmSync(run, { recursive: true, force: true });
      }
    }
  }

  // 2. Docker artifacts (opt-in).
  if (withDocker) {
    if (!dockerAvailable()) {
      eprintln("ultrasec clean: docker not available — skipping image/volume cleanup.");
    } else {
      for (const img of dockerImages()) {
        const present = docker(["images", "-q", img]);
        if (present.ok && present.out.trim()) {
          if (!dry) docker(["image", "rm", "-f", img]);
          removed.push(`image   ${img}`);
        }
      }
      const vols = docker(["volume", "ls", "-q", "-f", `name=${VOLUME_NAME_FILTER}`]);
      for (const v of vols.out
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)) {
        if (!dry) docker(["volume", "rm", v]);
        removed.push(`volume  ${v}`);
      }
    }
  }

  if (flagBool(args, "json")) {
    println(JSON.stringify({ dryRun: dry, removed, kept }, null, 2));
    return 0;
  }

  if (!removed.length && !kept.length) {
    println("ultrasec clean: nothing to remove.");
    return 0;
  }
  println(`ultrasec clean${dry ? " (dry-run)" : ""}:`);
  for (const r of removed) println(`  ${dry ? "would remove" : "removed"}  ${r}`);
  for (const k of kept) println(`  kept  ${k}`);
  if (kept.length) println(`  (deliverables preserved — pass --all to remove them too)`);
  if (!withDocker) println(`  (add --docker to also remove scanner images + the trivy cache volume)`);
  return 0;
}
