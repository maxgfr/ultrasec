import { describe, it, expect } from "vitest";
import type { Finding } from "../src/types.js";
import { compareVersions, fixedVersionOf, groupAdvisoriesByPackage } from "../src/deps.js";

function adv(over: Partial<Finding> = {}): Finding {
  return {
    id: over.id ?? "id0",
    category: "dep",
    title: over.title ?? "an advisory",
    severity: "medium",
    confidence: "high",
    message: "m",
    tool: "osv-scanner",
    status: "open",
    ...over,
  } as Finding;
}

describe("fixedVersionOf", () => {
  it("prefers the field", () => {
    expect(fixedVersionOf(adv({ fixedVersion: "2.0.0", message: "x (fixed in 1.0.0)" }))).toBe("2.0.0");
  });

  it("falls back to the prose the adapters used to spend it on", () => {
    // A dossier written before `fixedVersion` existed only has the sentence.
    // Re-rendering it must not answer "no fix published" for every advisory.
    expect(fixedVersionOf(adv({ message: "minimatch@8.0.4: ReDoS (fixed in 10.2.3)" }))).toBe("10.2.3");
  });

  it("reports nothing when no fix is published", () => {
    expect(fixedVersionOf(adv({ message: "lodash@4.17.21: prototype pollution" }))).toBeUndefined();
  });
});

describe("compareVersions", () => {
  it("orders numerically, not lexicographically", () => {
    // "1.10.0" < "1.9.0" as a string; telling someone to upgrade to 1.9.0
    // when 1.10.0 is the fix leaves them vulnerable.
    expect(compareVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareVersions("1.9.0", "1.10.0")).toBeLessThan(0);
    expect(compareVersions("2.0.0", "2.0.0")).toBe(0);
  });

  it("treats a missing segment as zero", () => {
    expect(compareVersions("1.0.0", "1.0")).toBe(0);
    expect(compareVersions("1.0.1", "1.0")).toBeGreaterThan(0);
  });

  it("ranks a pre-release below its own final release", () => {
    expect(compareVersions("1.0.0-rc1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "1.0.0-rc1")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0-rc2", "1.0.0-rc1")).toBeGreaterThan(0);
  });
});

describe("groupAdvisoriesByPackage", () => {
  it("rolls N advisories on one package into one row", () => {
    const rows = groupAdvisoriesByPackage([
      adv({ id: "a", pkg: "minimatch", version: "3.1.2", severity: "high", message: "x (fixed in 3.1.3)" }),
      adv({ id: "b", pkg: "minimatch", version: "9.0.5", severity: "medium", message: "y (fixed in 10.2.3)" }),
      adv({ id: "c", pkg: "axios", version: "1.0.0", severity: "low" }),
    ]);
    expect(rows.map((r) => r.pkg)).toEqual(["minimatch", "axios"]);
    const mm = rows[0]!;
    expect(mm.count).toBe(2);
    expect(mm.worst).toBe("high");
    expect(mm.versions).toEqual(["3.1.2", "9.0.5"]);
    // The highest fix is the one upgrade that clears the whole cluster.
    expect(mm.fixedVersion).toBe("10.2.3");
  });

  it("keeps every advisory addressable under its row", () => {
    // Grouping is for reading. No finding may vanish and no id may be rewritten.
    const rows = groupAdvisoriesByPackage([adv({ id: "a", pkg: "next" }), adv({ id: "b", pkg: "next" })]);
    expect(rows[0]!.advisories.map((x) => x.id).sort()).toEqual(["a", "b"]);
  });

  it("counts KEV members and takes the highest EPSS", () => {
    const rows = groupAdvisoriesByPackage([
      adv({ id: "a", pkg: "p", kev: true, epss: 0.4 }),
      adv({ id: "b", pkg: "p", kev: true, epss: 0.9 }),
      adv({ id: "c", pkg: "p", epss: 0.1 }),
    ]);
    expect(rows[0]!.kev).toBe(2);
    expect(rows[0]!.maxEpss).toBe(0.9);
  });

  it("takes the most reachable member — runtime beats toolchain", () => {
    const rows = groupAdvisoriesByPackage([adv({ id: "a", pkg: "p", reachability: "toolchain" }), adv({ id: "b", pkg: "p", reachability: "runtime" })]);
    expect(rows[0]!.reachability).toBe("runtime");
  });

  it("merges every lockfile location, deduped", () => {
    const rows = groupAdvisoriesByPackage([
      adv({ id: "a", pkg: "p", locations: [{ file: "a/pnpm-lock.yaml", line: 1, version: "1.0.0" }] }),
      adv({
        id: "b",
        pkg: "p",
        locations: [
          { file: "a/pnpm-lock.yaml", line: 1, version: "1.0.0" },
          { file: "b/pnpm-lock.yaml", line: 1, version: "2.0.0" },
        ],
      }),
    ]);
    expect(rows[0]!.locations).toHaveLength(2);
  });

  it("falls back to the single cited lockfile line when the correlator merged nothing", () => {
    const rows = groupAdvisoriesByPackage([adv({ id: "a", pkg: "p", version: "1.0.0", sink: { file: "pnpm-lock.yaml", line: 1 } })]);
    expect(rows[0]!.locations).toEqual([{ file: "pnpm-lock.yaml", line: 1, version: "1.0.0" }]);
  });

  it("does not merge unnamed advisories into one fake upgrade", () => {
    // Without `pkg` there is no cluster; one row each is honest, one row for
    // all of them would invent a package that does not exist.
    const rows = groupAdvisoriesByPackage([adv({ id: "a", title: "one" }), adv({ id: "b", title: "two" })]);
    expect(rows).toHaveLength(2);
  });

  it("sorts worst risk first", () => {
    const rows = groupAdvisoriesByPackage([adv({ id: "a", pkg: "low", risk: 10 }), adv({ id: "b", pkg: "hot", risk: 95 })]);
    expect(rows.map((r) => r.pkg)).toEqual(["hot", "low"]);
  });
});
