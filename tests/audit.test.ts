import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runAudit } from "../src/commands/audit.js";
import { runRender } from "../src/commands/render.js";
import { loadDossier } from "../src/store.js";
import { captureOutput, parseArgs } from "../src/util.js";

// `audit` is the one-command path: scan → pipeline → check → ONE report, then
// nothing but the deliverables. The incident it answers: a mid-size monorepo
// run left thirty-odd artifacts (2.7 MB of graph, every worklist twice, a 746 KB
// report of mostly dismissed rows) and the person who asked for "a report" had
// to write their own.

const FIXTURE = join(import.meta.dirname, "fixtures", "vuln-express");
const BUNDLE = join(import.meta.dirname, "..", "scripts", "ultrasec.mjs");
// Keyless and network-free, and independent of whatever scanners the machine has.
const OFFLINE = ["--offline", "--tools", "none", "--quiet"];

function tmpRun(): string {
  return join(mkdtempSync(join(tmpdir(), "ultrasec-audit-")), "run");
}

async function audit(run: string, extra: string[] = []): Promise<{ code: number; stdout: string }> {
  const r = await captureOutput(() => runAudit(parseArgs(["audit", "--repo", FIXTURE, "--out", run, ...OFFLINE, ...extra])));
  return { code: r.result, stdout: r.stdout };
}

const listing = (run: string) => readdirSync(run).sort();

describe("audit — one command, one report", () => {
  it("leaves exactly the report and the dossier it renders from", async () => {
    const run = tmpRun();
    const { code, stdout } = await audit(run);
    expect(code).toBe(0);
    expect(listing(run)).toEqual(["REPORT.md", "findings.json", "manifest.json"]);
    // One line with the path, one line of status — nothing else on stdout.
    const lines = stdout.split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(join(run, "REPORT.md"));
    expect(lines[1]).toMatch(/DRAFT — /);
  });

  it("never claims a clean audit when nothing was adjudicated: the report opens DRAFT, with why", async () => {
    const run = tmpRun();
    await audit(run);
    const md = readFileSync(join(run, "REPORT.md"), "utf8");
    const head = md.slice(0, 1500);
    expect(head).toContain("DRAFT — this is not a finished audit");
    expect(head).toMatch(/HIGH\/CRITICAL source-code candidate\(s\) never read/);
    expect(md).not.toMatch(/No confirmed issue/);
    // --strict turns the draft into a failing exit.
    expect((await audit(tmpRun(), ["--strict"])).code).toBe(1);
  });

  it("--html writes one self-contained page instead (no script, no external asset, light + dark)", async () => {
    const run = tmpRun();
    await audit(run, ["--html"]);
    expect(listing(run)).toEqual(["REPORT.html", "findings.json", "manifest.json"]);
    const html = readFileSync(join(run, "REPORT.html"), "utf8");
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toMatch(/<script|<link|<img|@import|src=/i);
    expect(html).toContain("prefers-color-scheme:dark");
    expect(html).toContain('id="1-executive-summary"');
    expect(html).toContain('href="#11-remediation-plan"');
    // --html --md: both, on request only.
    const both = tmpRun();
    await audit(both, ["--html", "--md"]);
    expect(listing(both)).toEqual(["REPORT.html", "REPORT.md", "findings.json", "manifest.json"]);
  });

  it("--keep-work keeps the JSON worklists and .work/, without the .md twins unless --md", async () => {
    const run = tmpRun();
    await audit(run, ["--keep-work"]);
    const files = listing(run);
    expect(files).toContain(".work");
    expect(files).toContain("VERIFY.todo.json");
    expect(files).toContain("GUARDS.todo.json");
    // The only Markdown besides the report: the dossier index and the
    // remediation-PRD draft, which is that stage's deliverable, not a twin.
    expect(files.filter((f) => f.endsWith(".md")).sort()).toEqual(["DOSSIER.md", "IMPLEMENT.md", "REPORT.md"]);
    expect(existsSync(join(run, ".work", "graph.json"))).toBe(true);
    expect(existsSync(join(run, "graph.json"))).toBe(false);

    const twins = tmpRun();
    await audit(twins, ["--keep-work", "--md"]);
    for (const f of ["VERIFY.md", "GUARDS.md", "TRIAGE.md", "CONTEXT.todo.md", "NARRATIVE.md"]) expect(existsSync(join(twins, f)), f).toBe(true);
  });

  it("a second audit merges into the run, so applied verdicts survive and the report reflects them", async () => {
    const run = tmpRun();
    await audit(run, ["--keep-work"]);
    const crit = loadDossier(run).findings.find((f) => f.severity === "critical")!;
    writeFileSync(
      join(run, "verdicts.json"),
      JSON.stringify([{ id: crit.id, verdict: "supported", note: "reached", exploitPath: "anyone · sends `;id` · gets a shell" }]),
    );
    const { runVerify } = await import("../src/commands/verify.js");
    await captureOutput(() => runVerify(parseArgs(["verify", "--run", run, "--apply", join(run, "verdicts.json")])));
    await audit(run);
    expect(loadDossier(run).findings.find((f) => f.id === crit.id)!.status).toBe("confirmed");
    const md = readFileSync(join(run, "REPORT.md"), "utf8");
    expect(md).toContain("anyone · sends `;id` · gets a shell");
  });

  it("refuses an unscannable --repo and a --powered with no agent CLI named", async () => {
    const r1 = await captureOutput(() => runAudit(parseArgs(["audit", "--repo", "/definitely/not/here", "--out", tmpRun()])));
    expect(r1.result).toBe(2);
    const r2 = await captureOutput(() => runAudit(parseArgs(["audit", "--repo", FIXTURE, "--out", tmpRun(), "--powered"])));
    expect(r2.result).toBe(2);
    expect(r2.stderr).toMatch(/--powered <cli>/);
  });

  it.runIf(existsSync(BUNDLE))("through the CLI, the journal does not recreate .work/ after the clean-up", () => {
    const run = tmpRun();
    execFileSync(process.execPath, [BUNDLE, "audit", "--repo", FIXTURE, "--out", run, ...OFFLINE], { encoding: "utf8", stdio: "pipe" });
    expect(listing(run)).toEqual(["REPORT.md", "findings.json", "manifest.json"]);
  });
});

describe("older run layouts keep working", () => {
  it("a run with graph.json / cache/ / JOURNAL.md at the top still loads and renders", async () => {
    const run = tmpRun();
    await audit(run, ["--keep-work"]);
    // Rewrite it into the pre-.work layout.
    const graph = readFileSync(join(run, ".work", "graph.json"), "utf8");
    execFileSync("rm", ["-rf", join(run, ".work")]);
    writeFileSync(join(run, "graph.json"), graph);
    mkdirSync(join(run, "cache"));
    writeFileSync(join(run, "JOURNAL.md"), "# ultrasec run journal\n");
    writeFileSync(join(run, "SUMMARY.md"), "old summary");

    const d = loadDossier(run);
    expect(d.graph.files.length).toBeGreaterThan(0);
    const r = await captureOutput(() => runRender(parseArgs(["render", "--run", run, "--draft"])));
    expect(r.result).toBe(0);
    expect(readFileSync(join(run, "REPORT.md"), "utf8")).toContain("# Security audit report");
    // The next write moves the graph under .work/ and leaves no second copy.
    const { runVerify } = await import("../src/commands/verify.js");
    await captureOutput(() => runVerify(parseArgs(["verify", "--run", run])));
    const { persistFindings } = await import("../src/stage.js");
    persistFindings(run, d, d.findings);
    expect(existsSync(join(run, ".work", "graph.json"))).toBe(true);
    expect(existsSync(join(run, "graph.json"))).toBe(false);
  });

  it("a cleaned run (no graph at all) still re-renders", async () => {
    const run = tmpRun();
    await audit(run);
    const r = await captureOutput(() => runRender(parseArgs(["render", "--run", run, "--draft", "--html"])));
    expect(r.result).toBe(0);
    expect(listing(run)).toEqual(["REPORT.html", "findings.json", "manifest.json"]);
  });
});
