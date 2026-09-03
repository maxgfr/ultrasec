import { chmodSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveCompatibleBash } from "../src/tools/registry.js";

const originalPath = process.env.PATH;

afterEach(() => {
  process.env.PATH = originalPath;
});

function fakeBash(dir: string, exitCode: number): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "bash");
  writeFileSync(path, `#!/bin/sh\nexit ${exitCode}\n`);
  chmodSync(path, 0o755);
  return path;
}

describe("package-checker Bash runtime", () => {
  it("skips an incompatible Bash 3 shim and selects the later Bash 4+ runtime", () => {
    const root = mkdtempSync(join(tmpdir(), "ultrasec-bash-"));
    const bash3 = fakeBash(join(root, "bash3"), 1);
    const bash5 = fakeBash(join(root, "bash5"), 0);
    process.env.PATH = [join(root, "bash3"), join(root, "bash5")].join(delimiter);

    expect(resolveCompatibleBash()).toBe(bash5);
    expect(resolveCompatibleBash()).not.toBe(bash3);
  });
});
