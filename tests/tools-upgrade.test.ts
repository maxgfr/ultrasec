import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { runTools, runUpgradeCommand } from "../src/commands/tools.js";
import { TOOLS, type ToolSpec } from "../src/tools/registry.js";
import type { ParsedArgs } from "../src/util.js";

// `tools --upgrade` (src/commands/tools.ts) — end-to-end coverage. No test here
// ever invokes a REAL package manager: `--dry-run` never executes anything, and
// the one real-execution test below shadows the manager binary ("brew") with a
// fake POSIX script on a PATH scoped to that single test, isolated from every
// real TOOLS entry so nothing on the actual dev/CI machine is ever touched.

function args(flags: Record<string, string | boolean>): ParsedArgs {
  return { _: ["tools"], flags };
}

function captureStdout(): { out: () => string; restore: () => void } {
  let buf = "";
  const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: any) => {
    buf += String(chunk);
    return true;
  });
  return { out: () => buf, restore: () => spy.mockRestore() };
}

function writeScript(path: string, body: string): void {
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
}

describe("runUpgradeCommand — the real execFileSync path, never throwing", () => {
  it("a fake command that exits 0 reports ok", () => {
    const r = runUpgradeCommand([[process.execPath, "-e", "process.exit(0)"]]);
    expect(r.ok).toBe(true);
  });

  it("a fake command that exits 1 reports failed, never throws", () => {
    expect(() => runUpgradeCommand([[process.execPath, "-e", "process.exit(1)"]])).not.toThrow();
    const r = runUpgradeCommand([[process.execPath, "-e", "process.exit(1)"]]);
    expect(r.ok).toBe(false);
  });

  it("a nonexistent binary is tolerated the same way (spawn ENOENT, not a throw)", () => {
    const r = runUpgradeCommand([["definitely-not-a-real-binary-xyz", "upgrade"]]);
    expect(r.ok).toBe(false);
    expect(r.detail.length).toBeGreaterThan(0);
  });
});

describe("tools --upgrade --dry-run — prints commands, executes nothing", () => {
  afterEach(() => {
    // Pop every fake entry this describe block may have pushed, defensively —
    // individual tests already clean up in try/finally, this is belt & braces.
    while (TOOLS.some((t) => t.name.startsWith("zzz-fake-dry-"))) {
      const i = TOOLS.findIndex((t) => t.name.startsWith("zzz-fake-dry-"));
      TOOLS.splice(i, 1);
    }
  });

  it("shows the exact command for a brew-shaped installed tool, a hint for unknown, and the self-updating note for package-checker", () => {
    const tmp = mkdtempSync(join(tmpdir(), "ultrasec-upgrade-dryrun-"));
    const brewBin = join(tmp, "opt", "homebrew", "bin");
    mkdirSync(brewBin, { recursive: true });
    writeScript(join(brewBin, "zzz-fake-dry-brew"), 'if [ "$1" = "--version" ]; then echo "zzz-fake-dry-brew 1.0.0"; fi\nexit 0');

    const unknownBin = join(tmp, "randomplace");
    mkdirSync(unknownBin, { recursive: true });
    writeScript(join(unknownBin, "zzz-fake-dry-unknown"), 'if [ "$1" = "--version" ]; then echo "zzz-fake-dry-unknown 1.0.0"; fi\nexit 0');

    const brewSpec: ToolSpec = {
      name: "zzz-fake-dry-brew",
      category: "sast",
      description: "fake brew-installed tool for the dry-run e2e test",
      languages: ["*"],
      install: { brew: "brew install zzz-fake-dry-brew" },
      runHint: "n/a",
    };
    const unknownSpec: ToolSpec = {
      name: "zzz-fake-dry-unknown",
      category: "sast",
      description: "fake tool at an unrecognized path for the dry-run e2e test",
      languages: ["*"],
      install: { url: "https://example.invalid/zzz-fake-dry-unknown" },
      runHint: "n/a",
    };
    TOOLS.push(brewSpec, unknownSpec);

    const originalPath = process.env.PATH;
    process.env.PATH = [brewBin, unknownBin, originalPath].filter(Boolean).join(delimiter);
    const cap = captureStdout();
    try {
      const code = runTools(args({ upgrade: true, "dry-run": true }));
      expect(code).toBe(0);
      const out = cap.out();
      expect(out).toContain("would run: brew upgrade zzz-fake-dry-brew");
      expect(out).toContain("zzz-fake-dry-unknown");
      expect(out).toContain("https://example.invalid/zzz-fake-dry-unknown");
      expect(out).not.toContain("would run: brew upgrade zzz-fake-dry-unknown");
      expect(out).toContain("package-checker");
      expect(out).toContain("self-updating at scan time");
      expect(out).toContain("docker-mode scans already refresh");
    } finally {
      cap.restore();
      process.env.PATH = originalPath;
      TOOLS.splice(TOOLS.indexOf(brewSpec), 1);
      TOOLS.splice(TOOLS.indexOf(unknownSpec), 1);
    }
  });

  it("default `tools` listing (no --upgrade) is unaffected by the flag's existence", () => {
    const cap = captureStdout();
    try {
      const code = runTools(args({}));
      expect(code).toBe(0);
      expect(cap.out()).toContain("ultrasec external scanners");
      expect(cap.out()).not.toContain("would run:");
    } finally {
      cap.restore();
    }
  });
});

describe("tools --upgrade (real execution) — isolated fake registry, never a real package manager", () => {
  it("a failing upgrade command yields status failed, and the command itself exits 0", () => {
    const tmp = mkdtempSync(join(tmpdir(), "ultrasec-upgrade-exec-fail-"));
    const shadowBin = join(tmp, "shadow-bin"); // fake `brew`, first on PATH
    const toolBin = join(tmp, "opt", "homebrew", "bin"); // the fake tool itself
    mkdirSync(shadowBin, { recursive: true });
    mkdirSync(toolBin, { recursive: true });
    writeScript(join(shadowBin, "brew"), "exit 1"); // every `brew` invocation fails
    writeScript(join(toolBin, "zzz-fake-e2e-tool"), 'if [ "$1" = "--version" ]; then echo "zzz-fake-e2e-tool 1.0.0"; fi\nexit 0');

    const fake: ToolSpec = {
      name: "zzz-fake-e2e-tool",
      category: "sast",
      description: "fake installed tool for the real-execution e2e test",
      languages: ["*"],
      install: { brew: "brew install zzz-fake-e2e-tool" },
      runHint: "n/a",
    };

    const originalPath = process.env.PATH;
    const originalTools = TOOLS.splice(0, TOOLS.length, fake); // isolate: ONLY the fake tool exists during this run
    process.env.PATH = [shadowBin, toolBin, originalPath].filter(Boolean).join(delimiter);
    const cap = captureStdout();
    try {
      const code = runTools(args({ upgrade: true }));
      expect(code).toBe(0); // per-tool failure is never fatal to the command
      const out = cap.out();
      expect(out).toContain("zzz-fake-e2e-tool");
      expect(out).toContain("failed");
    } finally {
      cap.restore();
      process.env.PATH = originalPath;
      TOOLS.splice(0, TOOLS.length, ...originalTools);
    }
  });

  it("an upgrade whose version string changes is reported upgraded old → new", () => {
    const tmp = mkdtempSync(join(tmpdir(), "ultrasec-upgrade-exec-ok-"));
    const shadowBin = join(tmp, "shadow-bin");
    const toolBin = join(tmp, "opt", "homebrew", "bin");
    mkdirSync(shadowBin, { recursive: true });
    mkdirSync(toolBin, { recursive: true });
    const marker = join(tmp, "version-marker.txt");
    writeFileSync(marker, "zzz-fake-e2e-tool 1.0.0");
    writeScript(join(shadowBin, "brew"), `echo "zzz-fake-e2e-tool 2.0.0" > "${marker}"\nexit 0`);
    writeScript(join(toolBin, "zzz-fake-e2e-tool"), `if [ "$1" = "--version" ]; then cat "${marker}"; fi\nexit 0`);

    const fake: ToolSpec = {
      name: "zzz-fake-e2e-tool",
      category: "sast",
      description: "fake installed tool for the real-execution e2e test",
      languages: ["*"],
      install: { brew: "brew install zzz-fake-e2e-tool" },
      runHint: "n/a",
    };

    const originalPath = process.env.PATH;
    const originalTools = TOOLS.splice(0, TOOLS.length, fake);
    process.env.PATH = [shadowBin, toolBin, originalPath].filter(Boolean).join(delimiter);
    const cap = captureStdout();
    try {
      const code = runTools(args({ upgrade: true }));
      expect(code).toBe(0);
      const out = cap.out();
      expect(out).toContain("upgraded");
      expect(out).toContain("zzz-fake-e2e-tool 1.0.0");
      expect(out).toContain("zzz-fake-e2e-tool 2.0.0");
    } finally {
      cap.restore();
      process.env.PATH = originalPath;
      TOOLS.splice(0, TOOLS.length, ...originalTools);
    }
  });
});
