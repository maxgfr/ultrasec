import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PACKAGE_CHECKER_SH, PACKAGE_CHECKER_TAG } from "../src/vendor/package-checker-script.js";
import { mapExport, splitPkgVersion } from "../src/tools/package-checker.js";

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const meta = JSON.parse(readFileSync(join(import.meta.dirname, "..", "src", "vendor", "package-checker.meta.json"), "utf8")) as {
  tag: string;
  scriptVersion: string;
  sha256: Record<string, string>;
};

describe("vendored package-checker.sh — drift gate mirrored in the test suite", () => {
  it("sha256 of PACKAGE_CHECKER_SH matches the .sh hash recorded in package-checker.meta.json", () => {
    expect(sha256(PACKAGE_CHECKER_SH)).toBe(meta.sha256["package-checker.sh"]);
  });

  it("PACKAGE_CHECKER_TAG matches the pinned meta.tag", () => {
    expect(PACKAGE_CHECKER_TAG).toBe(meta.tag);
  });

  it("the vendored script embeds a VERSION matching the pinned tag", () => {
    const version = PACKAGE_CHECKER_SH.match(/^VERSION="([^"]+)"/m)?.[1];
    expect(version).toBe(meta.scriptVersion);
    expect(`v${version}`).toBe(meta.tag);
  });
});

describe("splitPkgVersion", () => {
  it("splits on the LAST '@' (scoped-npm safe)", () => {
    expect(splitPkgVersion("@scope/name@1.2.3")).toEqual({ pkg: "@scope/name", version: "1.2.3" });
  });

  it("splits an unscoped package", () => {
    expect(splitPkgVersion("express@4.16.0")).toEqual({ pkg: "express", version: "4.16.0" });
  });

  it("no '@' at all: whole string is the pkg, version unset", () => {
    expect(splitPkgVersion("golang.org/x/net")).toEqual({ pkg: "golang.org/x/net" });
  });

  it("bare scoped package with no version: whole string is the pkg, version unset", () => {
    expect(splitPkgVersion("@scope/name")).toEqual({ pkg: "@scope/name" });
  });
});

describe("mapExport", () => {
  it("maps a realistic export into findings (pkg/version split, aliases, severity, file '.' strip)", () => {
    const findings = mapExport({
      vulnerabilities: [
        {
          package: "lodash@4.17.20",
          file: "./package-lock.json",
          ecosystem: "npm",
          severity: "high",
          ghsa: "GHSA-35jh-r3h4-6jhm",
          cve: "CVE-2021-23337",
          source: "ghsa",
        },
      ],
    });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.pkg).toBe("lodash");
    expect(f.version).toBe("4.17.20");
    expect(f.sink?.file).toBe("package-lock.json"); // leading "./" stripped
    expect(f.severity).toBe("high");
    expect(f.aliases).toEqual(expect.arrayContaining(["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"]));
    expect(f.cve).toBe("CVE-2021-23337");
    expect(f.tool).toBe("package-checker");
    expect(f.message).toContain("lodash@4.17.20");
    expect(f.message).toContain("npm");
    expect(f.message).toContain("via ghsa");
    expect(f.references).toEqual(["https://github.com/advisories/GHSA-35jh-r3h4-6jhm"]);
  });

  it("ghsa-only entry: ident/reference/aliases derive from ghsa, cve stays unset", () => {
    const [f] = mapExport({
      vulnerabilities: [{ package: "@acme/widget-core@2.3.1", file: "./package-lock.json", ecosystem: "npm", severity: "medium", ghsa: "GHSA-8x2m-9f3p-7q4r" }],
    });
    expect(f!.pkg).toBe("@acme/widget-core");
    expect(f!.aliases).toEqual(["GHSA-8x2m-9f3p-7q4r"]);
    expect(f!.cve).toBeUndefined();
    expect(f!.references).toEqual(["https://github.com/advisories/GHSA-8x2m-9f3p-7q4r"]);
  });

  it("cve-only entry: ident/reference/aliases derive from cve, no ghsa reference", () => {
    const [f] = mapExport({
      vulnerabilities: [{ package: "golang.org/x/net@0.7.0", file: "go.sum", ecosystem: "golang", severity: "high", cve: "CVE-2023-39325", source: "osv" }],
    });
    expect(f!.pkg).toBe("golang.org/x/net");
    expect(f!.version).toBe("0.7.0");
    expect(f!.aliases).toEqual(["CVE-2023-39325"]);
    expect(f!.cve).toBe("CVE-2023-39325");
    expect(f!.references).toEqual(["https://nvd.nist.gov/vuln/detail/CVE-2023-39325"]);
    expect(f!.sink?.file).toBe("go.sum"); // no leading "./" to strip — unchanged
  });

  it("tolerates empty / malformed input, never throws", () => {
    expect(mapExport(null)).toEqual([]);
    expect(mapExport({})).toEqual([]);
    expect(mapExport({ vulnerabilities: "not an array" })).toEqual([]);
    expect(mapExport({ vulnerabilities: [null, undefined, {}] })).toEqual([]); // {} has no package
  });
});

describe("package-checker adapter — materialization and export-file lifecycle", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "ultrasec-package-checker-"));
    process.env.ULTRASEC_CACHE_DIR = dir;
  });

  afterEach(() => {
    delete process.env.ULTRASEC_CACHE_DIR;
    rmSync(dir, { recursive: true, force: true });
  });

  it("scriptPath() writes the script once; a second call does not rewrite it", async () => {
    const { scriptPath } = await freshModule();
    const p = scriptPath();
    expect(existsSync(p)).toBe(true);
    expect(readFileSync(p, "utf8")).toBe(PACKAGE_CHECKER_SH);

    const mtimeBefore = statSync(p).mtimeMs;
    // Force the clock forward enough that a rewrite would be observable.
    await new Promise((r) => setTimeout(r, 10));
    const p2 = scriptPath();
    expect(p2).toBe(p);
    expect(statSync(p).mtimeMs).toBe(mtimeBefore); // untouched — not rewritten
  });

  it("parse(): reads the export at the adapter's export path, maps it, and deletes the file", async () => {
    const { packageChecker, exportPath } = await freshModule();
    const path = exportPath();
    mkdirSync(join(dir, "package-checker"), { recursive: true });
    writeFileSync(
      path,
      JSON.stringify({
        vulnerabilities: [
          {
            package: "lodash@4.17.20",
            file: "./package-lock.json",
            ecosystem: "npm",
            severity: "high",
            ghsa: "GHSA-35jh-r3h4-6jhm",
            cve: "CVE-2021-23337",
            source: "ghsa",
          },
        ],
      }),
    );
    const findings = packageChecker.parse("", "/repo");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.pkg).toBe("lodash");
    expect(existsSync(path)).toBe(false); // consumed
  });

  it("parse(): missing export file yields [] (nothing written, nothing to clean up)", async () => {
    const { packageChecker, exportPath } = await freshModule();
    expect(existsSync(exportPath())).toBe(false);
    expect(packageChecker.parse("", "/repo")).toEqual([]);
  });

  it("parse(): malformed export JSON yields [] and still deletes the file", async () => {
    const { packageChecker, exportPath } = await freshModule();
    const path = exportPath();
    mkdirSync(join(dir, "package-checker"), { recursive: true });
    writeFileSync(path, "not json");
    expect(packageChecker.parse("", "/repo")).toEqual([]);
    expect(existsSync(path)).toBe(false);
  });
});

/** Import package-checker.ts fresh so its module-state export path (memoized
 *  on first call, keyed off cacheDir() at that moment) picks up the
 *  ULTRASEC_CACHE_DIR set for this test rather than a value cached by an
 *  earlier test/module. Mirrors the yarnMajorCache reset pattern already used
 *  for pm-audit in tests/supply-chain-adapters.test.ts. */
async function freshModule(): Promise<typeof import("../src/tools/package-checker.js")> {
  vi.resetModules();
  return import("../src/tools/package-checker.js");
}
