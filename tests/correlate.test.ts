import { describe, it, expect } from "vitest";
import { correlate } from "../src/tools/correlate.js";
import { makeToolFinding } from "../src/tools/normalize.js";
import type { Finding } from "../src/types.js";

const dep = (tool: string, ident: string, sev: Finding["severity"], opts: { aliases?: string[]; pkg: string; version: string }) =>
  makeToolFinding({ tool, category: "dep", ident, title: ident, severity: sev, message: `${opts.pkg}@${opts.version}`, ...opts });

const sast = (tool: string, cwe: string, file: string, line: number, sev: Finding["severity"]) =>
  makeToolFinding({ tool, category: "sast", ident: `${tool}.rule:${file}:${line}`, title: "rule", severity: sev, message: "m", file, line, cwe });

describe("correlate — dep (SCA) cross-tool merge", () => {
  it("merges the same CVE on the same package@version across tools, unioning sources/aliases and taking max severity", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "GHSA-35jh-r3h4-6jhm", "medium", { aliases: ["CVE-2021-23337"], pkg: "lodash", version: "4.17.20" });
    const out = correlate([a, b]);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.sources).toEqual(["osv-scanner", "trivy"]);
    expect(out[0]!.cve).toBe("CVE-2021-23337");
    expect(out[0]!.aliases).toContain("GHSA-35JH-R3H4-6JHM");
    expect(out[0]!.confidence).toBe("high"); // corroborated by 2 tools
  });

  it("does NOT merge distinct vulns in the same package", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("trivy", "CVE-2020-8203", "high", { pkg: "lodash", version: "4.17.20" });
    expect(correlate([a, b])).toHaveLength(2);
  });

  it("does NOT merge the same CVE across different package versions", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "CVE-2021-23337", "high", { pkg: "lodash", version: "3.0.0" });
    expect(correlate([a, b])).toHaveLength(2);
  });
});

describe("correlate — non-dep merge by category+cwe+location", () => {
  it("merges two SAST tools flagging the same file:line+CWE", () => {
    const out = correlate([sast("semgrep", "CWE-89", "src/app.py", 42, "high"), sast("opengrep", "CWE-89", "src/app.py", 42, "medium")]);
    expect(out).toHaveLength(1);
    expect(out[0]!.sources).toEqual(["opengrep", "semgrep"]);
    expect(out[0]!.severity).toBe("high");
  });

  it("keeps findings at different lines separate", () => {
    expect(correlate([sast("semgrep", "CWE-89", "src/app.py", 42, "high"), sast("semgrep", "CWE-89", "src/app.py", 99, "high")])).toHaveLength(2);
  });
});

describe("correlate — invariants", () => {
  it("leaves taint candidates (tool=ultrasec) untouched", () => {
    const taint: Finding = { id: "t1", category: "taint", title: "flow", severity: "high", confidence: "medium", message: "m", tool: "ultrasec", status: "open" };
    const out = correlate([taint]);
    expect(out).toHaveLength(1);
    expect(out[0]!.tool).toBe("ultrasec");
    expect(out[0]).toBe(taint); // untouched, not reconstructed
  });

  it("is idempotent", () => {
    const a = dep("trivy", "CVE-2021-23337", "high", { pkg: "lodash", version: "4.17.20" });
    const b = dep("osv-scanner", "GHSA-1", "medium", { aliases: ["CVE-2021-23337"], pkg: "lodash", version: "4.17.20" });
    const once = correlate([a, b]);
    const twice = correlate(once);
    expect(twice).toHaveLength(once.length);
    expect(twice[0]!.sources).toEqual(once[0]!.sources);
  });

  it("returns [] for no input", () => {
    expect(correlate([])).toEqual([]);
  });
});
