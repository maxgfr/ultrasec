import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { runScan } from "../src/commands/scan.js";
import { parseArgs } from "../src/util.js";
import { runCheck } from "../src/commands/check.js";
import { runRender } from "../src/commands/render.js";

const { run } = vi.hoisted(() => ({ run: vi.fn() }));
vi.mock("../src/tools/run.js", async (original) => ({ ...(await original<typeof import("../src/tools/run.js")>()), orchestrate: run }));
vi.mock("../src/tools/sbom.js", () => ({ generateSbom: () => undefined }));
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.clearAllMocks();
});
async function scan(extra: string[], results: unknown[] = []) {
  const out = mkdtempSync(join(tmpdir(), "ultrasec-required-"));
  dirs.push(out);
  run.mockResolvedValue({ findings: [], toolsRun: [], results });
  const code = await runScan(parseArgs(["scan", "--repo", resolve("tests/fixtures/vuln-express"), "--out", out, "--offline", "--quiet", ...extra]));
  return { code, out, manifest: existsSync(join(out, "manifest.json")) ? JSON.parse(readFileSync(join(out, "manifest.json"), "utf8")) : undefined };
}
describe("required scanner completion policy", () => {
  it.each([false, true])("fails closed and writes usable evidence when the required scanner is absent (JSON=%s)", async (json) => {
    const result = await scan(
      ["--require-tools", "gitleaks", ...(json ? ["--json"] : [])],
      [{ name: "gitleaks", ran: false, ok: false, findings: [], note: "not installed" }],
    );
    expect(result.code).toBe(1);
    expect(result.manifest.scannerPolicy).toEqual({ required: ["gitleaks"], complete: false, incomplete: ["gitleaks"] });
    expect(readFileSync(join(result.out, "DOSSIER.md"), "utf8")).toContain("INCOMPLETE");
    expect(runCheck(parseArgs(["check", "--run", result.out]))).toBe(1);
    expect(runRender(parseArgs(["render", "--run", result.out]))).toBe(1);
    for (const file of ["SUMMARY.md", "REPORT.md", "index.html"])
      expect(readFileSync(join(result.out, file), "utf8")).toContain("Required scanners incomplete");
  });
  it("accepts a required scanner that actually ran and returned zero findings", async () => {
    const result = await scan(["--require-tools", "gitleaks", "--scope", "src"], [{ name: "gitleaks", ran: true, ok: true, findings: [], note: "0 findings" }]);
    expect(result.code).toBe(0);
    expect(result.manifest.scannerPolicy.complete).toBe(true);
    expect(run.mock.calls[0]?.[2].which).toEqual(["gitleaks"]);
  });
  it.each([[{ name: "gitleaks", ran: true, ok: false, findings: [], note: "timeout" }], []])(
    "fails when a required scanner failed or produced no outcome",
    async (...rows) => {
      expect((await scan(["--require-tools", "gitleaks"], rows)).code).toBe(1);
    },
  );
  it.each([["--no-tools"], ["--tools", "none"], ["--tools", "bandit"], ["--require-tools", "unknown-scanner"], ["--require-tools"], ["--require-tools", ","]])(
    "rejects contradictory/invalid policies before scanning: %j",
    async (...flags) => {
      const result = await scan(["--require-tools", "gitleaks", ...flags]);
      expect(result.code).toBe(2);
      expect(run).not.toHaveBeenCalled();
      expect(result.manifest).toBeUndefined();
    },
  );
  it("leaves optional scanner failures nonfatal without the new policy", async () => {
    const result = await scan([], [{ name: "gitleaks", ran: true, ok: false, findings: [], note: "timeout" }]);
    expect(result.code).toBe(0);
    expect(result.manifest.scannerPolicy).toBeUndefined();
  });

  it("rejects partial workspace execution only when the scanner is required", async () => {
    const partial = { name: "gitleaks", ran: true, ok: true, findings: [], note: "one workspace failed", workspaceCoverage: { total: 2, completed: 1 } };
    const required = await scan(["--require-tools", "gitleaks"], [partial]);
    expect(required.code).toBe(1);
    expect(required.manifest.toolStatus[0].workspaceCoverage).toEqual({ total: 2, completed: 1 });
    expect(required.manifest.scannerPolicy.complete).toBe(false);
    expect(runCheck(parseArgs(["check", "--run", required.out]))).toBe(1);
    expect(runRender(parseArgs(["render", "--run", required.out]))).toBe(1);
    expect((await scan([], [partial])).code).toBe(0);
  });

  it("accepts a valid resumed scanner result as reused execution evidence", async () => {
    const result = await scan(
      ["--require-tools", "gitleaks", "--resume"],
      [{ name: "gitleaks", ran: true, ok: true, findings: [], note: "0 findings · cached (--resume)" }],
    );
    expect(result.code).toBe(0);
    expect(result.manifest.toolStatus[0].note).toContain("cached");
  });
});
