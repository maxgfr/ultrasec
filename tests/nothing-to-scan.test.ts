import { describe, it, expect } from "vitest";
import { runAdapter, type ToolAdapter } from "../src/tools/run.js";
import { osvScanner } from "../src/tools/osv.js";

// osv-scanner exits non-zero with "No package sources found" on a tree with no
// lockfile. The run was reported as FAILED, with the tool's stderr — elapsed
// times included — copied into the status note: a repo with nothing to audit read
// as a broken scanner, and two identical scans printed different JSON.

const exitWith = (stderr: string, code: number): ToolAdapter => ({
  ...osvScanner,
  name: "fake-osv",
  command: () => [process.execPath],
  argv: () => ["-e", `process.stderr.write(${JSON.stringify(stderr)}); process.exit(${code})`],
});

describe("a scanner with nothing to scan is skipped, not failed", () => {
  it("maps osv-scanner's 'No package sources found' to a stable skip note", async () => {
    const msg =
      "Scanning dir /x\nEnd status: 2 dirs visited, 7 inodes visited, 0 Extract calls, 173.333µs elapsed\nNo package sources found, --help for usage information.\n";
    const r = await runAdapter(exitWith(msg, 128), "/tmp");
    expect(r.ran).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.note).toBe(osvScanner.nothingToScan!.note);
    expect(r.note).not.toMatch(/µs|elapsed/);
  });

  it("still reports a genuine failure as failed", async () => {
    const r = await runAdapter(exitWith("fatal: database download failed\n", 1), "/tmp");
    expect(r.ran).toBe(true);
    expect(r.ok).toBe(false);
    expect(r.note).toMatch(/^run failed:/);
  });
});
