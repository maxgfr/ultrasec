import { describe, it, expect, vi } from "vitest";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { grype } from "../src/tools/grype.js";
import { pipAudit } from "../src/tools/pip-audit.js";
import { trivy } from "../src/tools/trivy.js";
import { correlate } from "../src/tools/correlate.js";
import { detect } from "../src/tools/registry.js";
import { npmAudit, pnpmAudit, yarnAudit, parseNpmV6Advisories, parseNpmV7 } from "../src/tools/pm-audit.js";

const fix = (name: string) => readFileSync(join(import.meta.dirname, "fixtures", "tool-output", name), "utf8");

describe("grype adapter", () => {
  const f = grype.parse(fix("grype.json"), "/repo");
  it("maps a GHSA match with a related CVE (aliases carry both)", () => {
    expect(f).toHaveLength(2);
    const lodash = f.find((x) => x.pkg === "lodash")!;
    expect(lodash.version).toBe("4.17.15");
    expect(lodash.sink).toEqual({ file: "package-lock.json", line: 1 });
    expect(lodash.severity).toBe("high"); // label "High"
    expect(lodash.aliases).toEqual(expect.arrayContaining(["GHSA-jf85-cpcp-j695", "CVE-2020-8203"]));
    expect(lodash.cve).toBe("CVE-2020-8203"); // makeToolFinding auto-picks the CVE out of aliases
    expect(lodash.message).toContain("lodash@4.17.15");
    expect(lodash.message).toContain("fixed in 4.17.21");
    expect(lodash.tool).toBe("grype");
  });

  it("falls back to the CVSS base score when severity is missing/Unknown", () => {
    const urllib3 = f.find((x) => x.pkg === "urllib3")!;
    expect(urllib3.version).toBe("1.26.5");
    expect(urllib3.sink).toEqual({ file: "requirements.txt", line: 1 });
    // vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → base score 7.5 → high
    expect(urllib3.severity).toBe("high");
    expect(urllib3.cve).toBe("CVE-2023-43804");
    expect(urllib3.message).not.toContain("fixed in"); // no fix.versions in the fixture
  });

  it("tolerates empty / malformed input", () => {
    expect(grype.parse("", "/repo")).toEqual([]);
    expect(grype.parse("{}", "/repo")).toEqual([]);
    expect(grype.parse("not json", "/repo")).toEqual([]);
  });

  it("tolerates falsy matches entries (null/undefined)", () => {
    expect(grype.parse(JSON.stringify({ matches: [null] }), "/repo")).toEqual([]);
    expect(grype.parse(JSON.stringify({ matches: [undefined] }), "/repo")).toEqual([]);
  });

  it("argv: switches to the SBOM target when ctx.sbom is set, else scans the dir", () => {
    expect(grype.argv("/repo")).toEqual(["dir:/repo", "-o", "json", "-q"]);
    expect(grype.argv("/repo", {})).toEqual(["dir:/repo", "-o", "json", "-q"]);
    expect(grype.argv("/repo", { sbom: "/abs/run/sbom.json" })).toEqual(["sbom:/abs/run/sbom.json", "-o", "json", "-q"]);
  });
});

describe("pip-audit adapter", () => {
  const f = pipAudit.parse(fix("pip-audit.json"), "/repo");
  it("maps a vuln whose aliases carry the CVE, default severity medium", () => {
    expect(f).toHaveLength(2);
    const django = f.find((x) => x.pkg === "django")!;
    expect(django.version).toBe("3.0.2");
    expect(django.sink).toEqual({ file: "requirements.txt", line: 1 });
    expect(django.severity).toBe("medium"); // pip-audit emits no severity
    expect(django.aliases).toEqual(expect.arrayContaining(["PYSEC-2021-9", "CVE-2021-3281"]));
    expect(django.cve).toBe("CVE-2021-3281");
    expect(django.tool).toBe("pip-audit");
  });

  it("includes fix_versions in the message when present", () => {
    const requests = f.find((x) => x.pkg === "requests")!;
    expect(requests.version).toBe("2.25.0");
    expect(requests.message).toContain("fixed in 2.31.0");
    expect(requests.aliases).toEqual(["GHSA-x84v-xcm2-53pg"]);
  });

  it("tolerates empty / malformed input", () => {
    expect(pipAudit.parse("", "/repo")).toEqual([]);
    expect(pipAudit.parse("{}", "/repo")).toEqual([]);
    expect(pipAudit.parse("not json", "/repo")).toEqual([]);
  });

  it("tolerates falsy vuln entries (null/undefined) — regression for parse contract", () => {
    expect(pipAudit.parse(JSON.stringify({ dependencies: [{ name: "x", version: "1.0", vulns: [null] }] }), "/repo")).toEqual([]);
    expect(pipAudit.parse(JSON.stringify({ dependencies: [{ name: "x", version: "1.0", vulns: [undefined] }] }), "/repo")).toEqual([]);
  });

  it("applicable(): null (run) when requirements.txt exists, a skip note otherwise", () => {
    const withReq = mkdtempSync(join(tmpdir(), "ultrasec-pip-audit-"));
    writeFileSync(join(withReq, "requirements.txt"), "requests==2.25.0\n");
    expect(pipAudit.applicable!(withReq)).toBeNull();

    const withoutReq = mkdtempSync(join(tmpdir(), "ultrasec-pip-audit-"));
    expect(pipAudit.applicable!(withoutReq)).toBe("no requirements.txt");
  });
});

describe("npm-audit adapter", () => {
  it("dispatches the npm-6 shape (advisories key) to the v6 parser", () => {
    const f = npmAudit.parse(fix("npm-audit-v6.json"), "/repo");
    expect(f).toHaveLength(3);

    const lodash = f.find((x) => x.pkg === "lodash")!;
    expect(lodash.version).toBe("4.17.20");
    expect(lodash.sink).toEqual({ file: "package-lock.json", line: 1 });
    expect(lodash.severity).toBe("high");
    expect(lodash.aliases).toEqual(expect.arrayContaining(["GHSA-35JH-R3H4-6JHM", "CVE-2021-23337"]));
    expect(lodash.cve).toBe("CVE-2021-23337");
    expect(lodash.tool).toBe("npm-audit");

    const scoped = f.find((x) => x.pkg === "@babel/traverse")!;
    expect(scoped.severity).toBe("medium"); // "moderate" -> medium
    expect(scoped.aliases).toEqual(expect.arrayContaining(["GHSA-67HX-6X53-JW92", "CVE-2023-45133"]));

    const minimist = f.find((x) => x.pkg === "minimist")!;
    expect(minimist.severity).toBe("critical");
    expect(minimist.cwe).toBe("CWE-1321");
  });

  it("dispatches the npm-7 shape (auditReportVersion: 2) to the v7 parser, skipping string via pointers", () => {
    const f = npmAudit.parse(fix("npm-audit-v7.json"), "/repo");
    // 3, not 4: "meow"'s via is a pure string pointer ("trim-newlines") and must
    // NOT produce its own finding (anti-double-count).
    expect(f).toHaveLength(3);
    expect(f.some((x) => x.pkg === "meow")).toBe(false);

    const trimNewlines = f.find((x) => x.pkg === "trim-newlines")!;
    expect(trimNewlines.severity).toBe("medium"); // "moderate" -> medium
    expect(trimNewlines.version).toBeUndefined(); // not reliably present in this shape
    expect(trimNewlines.message).toContain("<3.0.1"); // via.range surfaced in the message instead
    expect(trimNewlines.aliases).toEqual(expect.arrayContaining(["GHSA-7P7H-4MM5-852V"]));

    const scoped = f.find((x) => x.pkg === "@scope/vuln-pkg")!;
    expect(scoped.severity).toBe("high");
    expect(scoped.aliases).toEqual(expect.arrayContaining(["GHSA-ABCD-EFGH-IJKL"]));
  });

  it("npm-7 parser: via entry without severity falls back to parent vulnerability severity", () => {
    const f = npmAudit.parse(fix("npm-audit-v7.json"), "/repo");
    const missingSeverity = f.find((x) => x.pkg === "missing-severity-pkg")!;
    expect(missingSeverity).toBeDefined();
    // via.severity is absent, should inherit parent vulnerabilities[name].severity
    expect(missingSeverity.severity).toBe("low");
    expect(missingSeverity.aliases).toEqual(expect.arrayContaining(["GHSA-XXXX-YYYY-ZZZZ"]));
  });

  it("tolerates empty / malformed / unrecognized input", () => {
    expect(npmAudit.parse("", "/repo")).toEqual([]);
    expect(npmAudit.parse("{}", "/repo")).toEqual([]);
    expect(npmAudit.parse("not json", "/repo")).toEqual([]);
    expect(npmAudit.parse(JSON.stringify({ foo: "bar" }), "/repo")).toEqual([]);
  });

  it("applicable(): null when package-lock.json or npm-shrinkwrap.json exists, a skip note otherwise", () => {
    const withLock = mkdtempSync(join(tmpdir(), "ultrasec-npm-audit-"));
    writeFileSync(join(withLock, "package-lock.json"), "{}");
    expect(npmAudit.applicable!(withLock)).toBeNull();

    const withShrinkwrap = mkdtempSync(join(tmpdir(), "ultrasec-npm-audit-"));
    writeFileSync(join(withShrinkwrap, "npm-shrinkwrap.json"), "{}");
    expect(npmAudit.applicable!(withShrinkwrap)).toBeNull();

    const withoutLock = mkdtempSync(join(tmpdir(), "ultrasec-npm-audit-"));
    expect(npmAudit.applicable!(withoutLock)).toBe("no package-lock.json");
  });

  it("command(): probes the real npm binary, not the adapter name", () => {
    expect(npmAudit.command!()).toEqual(detect("npm").installed ? ["npm"] : null);
  });
});

describe("pnpm-audit adapter (reuses the npm-v6 parser — pnpm emits the same legacy shape)", () => {
  const f = pnpmAudit.parse(fix("pnpm-audit.json"), "/repo");

  it("maps advisories with file fixed to pnpm-lock.yaml and tool credited to pnpm-audit", () => {
    expect(f).toHaveLength(3);
    for (const x of f) {
      expect(x.sink).toEqual({ file: "pnpm-lock.yaml", line: 1 });
      expect(x.tool).toBe("pnpm-audit");
    }
  });

  it("moderate severity maps to medium, scoped package name preserved", () => {
    const ansiRegex = f.find((x) => x.pkg === "ansi-regex")!;
    expect(ansiRegex.severity).toBe("medium");
    expect(ansiRegex.aliases).toEqual(expect.arrayContaining(["GHSA-93Q8-GQ69-WQMW", "CVE-2021-3807"]));

    const scoped = f.find((x) => x.pkg === "@scope/pnpm-vuln")!;
    expect(scoped.severity).toBe("high");
    expect(scoped.version).toBe("3.1.0");
  });

  it("extracts the GHSA from the advisory URL when github_advisory_id is absent", () => {
    const minimatch = f.find((x) => x.pkg === "minimatch")!;
    expect(minimatch.aliases).toEqual(expect.arrayContaining(["GHSA-F8Q6-P94X-37V3", "CVE-2022-3517"]));
  });

  it("tolerates empty / malformed input", () => {
    expect(pnpmAudit.parse("", "/repo")).toEqual([]);
    expect(pnpmAudit.parse("{}", "/repo")).toEqual([]);
    expect(pnpmAudit.parse("not json", "/repo")).toEqual([]);
  });

  it("applicable(): null when pnpm-lock.yaml exists, a skip note otherwise", () => {
    const withLock = mkdtempSync(join(tmpdir(), "ultrasec-pnpm-audit-"));
    writeFileSync(join(withLock, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    expect(pnpmAudit.applicable!(withLock)).toBeNull();

    const withoutLock = mkdtempSync(join(tmpdir(), "ultrasec-pnpm-audit-"));
    expect(pnpmAudit.applicable!(withoutLock)).toBe("no pnpm-lock.yaml");
  });

  it("command(): probes the real pnpm binary, not the adapter name", () => {
    expect(pnpmAudit.command!()).toEqual(detect("pnpm").installed ? ["pnpm"] : null);
  });
});

describe("yarn-audit adapter — classic dialect (yarn 1.x)", () => {
  const f = yarnAudit.parse(fix("yarn-audit-classic.ndjson"), "/repo");

  it("maps only auditAdvisory lines, ignoring auditSummary/info lines", () => {
    expect(f).toHaveLength(2);
    for (const x of f) {
      expect(x.sink).toEqual({ file: "yarn.lock", line: 1 });
      expect(x.tool).toBe("yarn-audit");
    }
  });

  it("high severity lodash advisory, moderate scoped advisory maps to medium", () => {
    const lodash = f.find((x) => x.pkg === "lodash")!;
    expect(lodash.severity).toBe("high");
    expect(lodash.aliases).toEqual(expect.arrayContaining(["GHSA-JF85-CPCP-J695", "CVE-2020-8203"]));
    expect(lodash.version).toBe("4.17.15");

    const scoped = f.find((x) => x.pkg === "@scope/yarn-vuln")!;
    expect(scoped.severity).toBe("medium"); // "moderate" -> medium
    expect(scoped.aliases).toEqual(expect.arrayContaining(["GHSA-2222-3333-4444", "CVE-2021-1111"]));
  });

  it("tolerates empty / malformed / unrecognized input, never throws", () => {
    expect(yarnAudit.parse("", "/repo")).toEqual([]);
    expect(yarnAudit.parse("not json", "/repo")).toEqual([]);
    expect(() => yarnAudit.parse('{"type":"unknown"}\n{garbage', "/repo")).not.toThrow();
  });
});

describe("yarn-audit adapter — berry dialect (yarn 2+)", () => {
  const f = yarnAudit.parse(fix("yarn-audit-berry.ndjson"), "/repo");

  it("maps {value, children} lines, skipping unrecognized shapes silently", () => {
    expect(f).toHaveLength(2);
  });

  it("severity from children.Severity, version from the first Tree Versions entry, GHSA+CVE aliases", () => {
    const minimist = f.find((x) => x.pkg === "minimist")!;
    expect(minimist.severity).toBe("critical");
    expect(minimist.version).toBe("1.2.0");
    expect(minimist.aliases).toEqual(expect.arrayContaining(["GHSA-VH95-RMGR-6W4M", "CVE-2020-7598"]));
    expect(minimist.sink).toEqual({ file: "yarn.lock", line: 1 });
    expect(minimist.tool).toBe("yarn-audit");

    const scoped = f.find((x) => x.pkg === "@scope/berry-vuln")!;
    expect(scoped.severity).toBe("medium"); // "moderate" -> medium
    expect(scoped.version).toBe("1.4.0"); // first of ["1.4.0", "1.4.2"]
  });
});

describe("yarn-audit adapter — applicable() and command()/argv() version dispatch", () => {
  it("applicable(): null when yarn.lock exists, a skip note otherwise", () => {
    const withLock = mkdtempSync(join(tmpdir(), "ultrasec-yarn-audit-"));
    writeFileSync(join(withLock, "yarn.lock"), "# yarn lockfile v1\n");
    expect(yarnAudit.applicable!(withLock)).toBeNull();

    const withoutLock = mkdtempSync(join(tmpdir(), "ultrasec-yarn-audit-"));
    expect(yarnAudit.applicable!(withoutLock)).toBe("no yarn.lock");
  });

  it("command() never throws, and command()/argv() agree with the real yarn on this host (classic vs berry)", () => {
    let expectedMajor: number | null;
    try {
      const out = execFileSync("yarn", ["--version"], { stdio: ["ignore", "pipe", "ignore"] })
        .toString()
        .trim();
      const n = Number.parseInt(out.split(".")[0] ?? "", 10);
      expectedMajor = Number.isFinite(n) ? n : null;
    } catch {
      expectedMajor = null;
    }

    let cmd: string[] | null = null;
    expect(() => {
      cmd = yarnAudit.command!();
    }).not.toThrow();
    const argv = yarnAudit.argv("/repo");

    if (expectedMajor === null) {
      expect(cmd).toBeNull();
    } else if (expectedMajor >= 2) {
      expect(cmd).toEqual(["yarn", "npm"]);
      expect(argv).toEqual(["audit", "--json", "--recursive"]);
    } else {
      expect(cmd).toEqual(["yarn"]);
      expect(argv).toEqual(["audit", "--json"]);
    }
  });

  it("command() gracefully returns null when the yarn binary is absent / --version fails", async () => {
    vi.resetModules();
    vi.doMock("node:child_process", async (importOriginal) => {
      const original = await importOriginal<typeof import("node:child_process")>();
      return {
        ...original,
        execFileSync: () => {
          throw new Error("ENOENT: yarn not found");
        },
      };
    });
    try {
      const fresh = await import("../src/tools/pm-audit.js");
      expect(() => fresh.yarnAudit.command!()).not.toThrow();
      expect(fresh.yarnAudit.command!()).toBeNull();
    } finally {
      vi.doUnmock("node:child_process");
      vi.resetModules();
    }
  });
});

describe("pm-audit shared parsers — direct unit coverage", () => {
  it("parseNpmV6Advisories: unknown/empty/malformed shapes yield []", () => {
    expect(parseNpmV6Advisories({}, "pnpm-lock.yaml", "pnpm-audit")).toEqual([]);
    expect(parseNpmV6Advisories({ advisories: null }, "pnpm-lock.yaml", "pnpm-audit")).toEqual([]);
    expect(parseNpmV6Advisories({ advisories: { x: null } }, "pnpm-lock.yaml", "pnpm-audit")).toEqual([]);
  });

  it("parseNpmV6Advisories: wrong-typed cves field (not an array) never throws, still creates finding", () => {
    const resultWithObject = parseNpmV6Advisories(
      {
        advisories: {
          x: {
            id: 1,
            module_name: "pkg",
            title: "Vuln",
            cves: {} // wrong type: object instead of array
          }
        }
      },
      "package-lock.json",
      "npm-audit"
    );
    expect(resultWithObject).toHaveLength(1);
    expect(resultWithObject[0]!.pkg).toBe("pkg");
    expect(resultWithObject[0]!.title).toBe("Vuln");
    // The finding is created, just without the CVE (cves was malformed)
    expect(resultWithObject[0]!.aliases).toEqual(["1"]); // only the advisory id, no CVE

    const resultWithBoolean = parseNpmV6Advisories(
      {
        advisories: {
          x: {
            id: 2,
            module_name: "pkg2",
            title: "Vuln2",
            cves: true // wrong type: boolean instead of array
          }
        }
      },
      "package-lock.json",
      "npm-audit"
    );
    expect(resultWithBoolean).toHaveLength(1);
    expect(resultWithBoolean[0]!.pkg).toBe("pkg2");
  });

  it("pnpmAudit: wrong-typed cves field never throws (regression for parse contract)", () => {
    const result = pnpmAudit.parse(
      JSON.stringify({
        advisories: {
          x: {
            id: 1,
            module_name: "pkg",
            title: "Vuln",
            cves: {}
          }
        }
      }),
      "/repo"
    );
    expect(result).toHaveLength(1);
    expect(result[0]!.pkg).toBe("pkg");
    // The key point: parsing never throws, it still produces a finding
  });

  it("parseNpmV7: unknown/empty/malformed shapes yield []", () => {
    expect(parseNpmV7({}, "package-lock.json")).toEqual([]);
    expect(parseNpmV7({ vulnerabilities: null }, "package-lock.json")).toEqual([]);
    expect(parseNpmV7({ vulnerabilities: { x: null } }, "package-lock.json")).toEqual([]);
    expect(parseNpmV7({ vulnerabilities: { x: { via: null } } }, "package-lock.json")).toEqual([]);
  });

  it("parseNpmV7: wrong-typed via field (not an array) never throws", () => {
    // When via is not an array, the guard treats it as empty array, so no findings
    // from this vulnerability. This is the correct defensive behavior.
    const result = parseNpmV7(
      {
        vulnerabilities: {
          x: {
            via: {} // wrong type: object instead of array
          }
        }
      },
      "package-lock.json"
    );
    // Parsing succeeds without throwing; no findings because via is not iterable
    expect(result).toEqual([]);
  });

  it("npmAudit: wrong-typed via field never throws (regression for parse contract)", () => {
    const result = npmAudit.parse(
      JSON.stringify({
        auditReportVersion: 2,
        vulnerabilities: {
          x: {
            via: {}
          }
        }
      }),
      "/repo"
    );
    // The key point: parsing never throws when via is wrong-typed
    expect(result).toEqual([]);
  });
});

describe("npm-audit correlates with trivy on a shared GHSA/CVE (cross-tool dedup)", () => {
  it("merges the shared lodash advisory into one finding with both tool sources, keeps the rest distinct", () => {
    const trivyFindings = trivy.parse(fix("trivy.json"), "/repo");
    const npmFindings = npmAudit.parse(fix("npm-audit-v6.json"), "/repo");
    const merged = correlate([...trivyFindings, ...npmFindings]);

    const lodash = merged.find((f) => f.pkg === "lodash")!;
    expect(lodash).toBeDefined();
    expect(lodash.sources).toEqual(["npm-audit", "trivy"]);
    expect(lodash.confidence).toBe("high"); // corroborated by 2 tools
    expect(lodash.severity).toBe("high");
    expect(lodash.aliases).toEqual(expect.arrayContaining(["GHSA-35JH-R3H4-6JHM", "CVE-2021-23337"]));

    // trivy: 1 dep (lodash) + 1 secret + 1 config = 3; npm-audit: 3 dep advisories.
    // lodash merges 1:1 -> 6 raw findings collapse to 5.
    expect(merged).toHaveLength(5);
    expect(merged.filter((f) => f.category === "dep")).toHaveLength(3);
  });
});
