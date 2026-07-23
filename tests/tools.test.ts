import { describe, it, expect } from "vitest";
import { TOOLS, detect, toolStatuses, type ToolSpec } from "../src/tools/registry.js";
import { ADAPTERS } from "../src/tools/index.js";
import { CATEGORIES } from "../src/types.js";

// Deliberate exceptions to "every TOOLS entry has a runnable adapter" — a TOOLS
// row that documents a scanner ultrasec knows about but doesn't (yet) drive.
// This is where a future one gets recorded, not a place to quietly grow drift
// back in.
const TOOLS_WITHOUT_ADAPTER: string[] = [
  // syft is an SBOM GENERATOR (src/tools/sbom.ts's generateSbom), not a findings
  // producer — it has no ToolAdapter/argv/parse, so it never appears in ADAPTERS.
  "syft",
];

describe("tool registry", () => {
  it("every tool has a valid category and at least one install hint", () => {
    for (const t of TOOLS) {
      expect(CATEGORIES).toContain(t.category);
      expect(t.name).toMatch(/^[a-z0-9-]+$/);
      expect(t.languages.length).toBeGreaterThan(0);
      expect(Object.keys(t.install).length).toBeGreaterThan(0);
      expect(t.runHint.length).toBeGreaterThan(0);
    }
  });

  it("tool names are unique", () => {
    const names = TOOLS.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("has at least one primary SAST and one primary SCA tool", () => {
    expect(TOOLS.some((t) => t.primary && t.category === "sast")).toBe(true);
    expect(TOOLS.some((t) => t.primary && t.category === "dep")).toBe(true);
  });

  // Regression guard for the drift this task fixed: TOOLS advertised grype,
  // pip-audit and osv-scalibr while ADAPTERS ran none of them — `tools` showed
  // them installed, nothing ever executed them. Every adapter must be a real,
  // advertised tool, and every advertised tool must be a real, runnable adapter
  // unless explicitly allowlisted above.
  it("every adapter has a matching TOOLS entry", () => {
    const toolNames = new Set(TOOLS.map((t) => t.name));
    for (const a of ADAPTERS) expect(toolNames, `ADAPTERS entry "${a.name}" has no TOOLS spec`).toContain(a.name);
  });

  it("every TOOLS entry has an adapter, unless explicitly allowlisted in TOOLS_WITHOUT_ADAPTER", () => {
    const adapterNames = new Set(ADAPTERS.map((a) => a.name));
    for (const t of TOOLS) {
      if (TOOLS_WITHOUT_ADAPTER.includes(t.name)) continue;
      expect(adapterNames, `TOOLS entry "${t.name}" has no adapter (add one or list it in TOOLS_WITHOUT_ADAPTER)`).toContain(t.name);
    }
  });
});

describe("detect", () => {
  it("finds a binary that is certainly present (node)", () => {
    expect(detect("node").installed).toBe(true);
  });

  it("reports a bogus binary as absent", () => {
    expect(detect("definitely-not-a-real-binary-xyz").installed).toBe(false);
  });
});

describe("toolStatuses", () => {
  it("returns one status per tool, name-sorted, each with an installed flag", () => {
    const s = toolStatuses();
    expect(s.length).toBe(TOOLS.length);
    expect(s.map((t) => t.name)).toEqual([...s.map((t) => t.name)].sort());
    for (const t of s) expect(typeof t.installed).toBe("boolean");
  });

  it("a spec's own detect() overrides the PATH probe (e.g. a vendored, non-PATH script)", () => {
    const fake: ToolSpec = {
      name: "zzz-fake-vendored-tool",
      category: "sast",
      description: "d",
      languages: ["*"],
      install: { url: "https://example.invalid" },
      runHint: "n/a",
      detect: () => ({ installed: true, version: "9.9.9" }),
    };
    TOOLS.push(fake);
    try {
      const found = toolStatuses().find((t) => t.name === "zzz-fake-vendored-tool");
      expect(found?.installed).toBe(true);
      expect(found?.version).toBe("9.9.9");
    } finally {
      TOOLS.pop();
    }
  });
});
