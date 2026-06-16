import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { trivy } from "../src/tools/trivy.js";
import { gitleaks } from "../src/tools/gitleaks.js";
import { osvScanner } from "../src/tools/osv.js";
import { semgrep, opengrep } from "../src/tools/semgrep.js";
import { cargoAudit } from "../src/tools/cargo-audit.js";
import { govulncheck } from "../src/tools/govulncheck.js";
import { cvssBaseScore, scoreToSeverity, deriveSeverity } from "../src/tools/cvss.js";
import { parseJsonStream } from "../src/tools/normalize.js";

const fix = (name: string) => readFileSync(join(import.meta.dirname, "fixtures", "tool-output", name), "utf8");

describe("trivy adapter", () => {
  const f = trivy.parse(fix("trivy.json"), "/repo");
  it("produces a dep, a secret, and a config finding", () => {
    expect(f.map((x) => x.category).sort()).toEqual(["config", "dep", "secret"]);
  });
  it("maps the CVE with CWE, severity and fix info", () => {
    const dep = f.find((x) => x.category === "dep")!;
    expect(dep.severity).toBe("high");
    expect(dep.cwe).toBe("CWE-78");
    expect(dep.message).toContain("4.17.21");
    expect(dep.tool).toBe("trivy");
  });
  it("attaches the Result.Target as the secret/config location", () => {
    const secret = f.find((x) => x.category === "secret")!;
    expect(secret.severity).toBe("critical");
    expect(secret.sink).toEqual({ file: "app/config.py", line: 12 });
    const cfg = f.find((x) => x.category === "config")!;
    expect(cfg.sink).toEqual({ file: "Dockerfile", line: 1 });
  });
  it("tolerates missing Results", () => {
    expect(trivy.parse("{}", "/repo")).toEqual([]);
    expect(trivy.parse("", "/repo")).toEqual([]);
  });
});

describe("gitleaks adapter", () => {
  const f = gitleaks.parse(fix("gitleaks.json"), "/repo");
  it("maps a secret with a fixed high severity and CWE-798", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("secret");
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.cwe).toBe("CWE-798");
    expect(f[0]!.sink).toEqual({ file: "README.md", line: 70 });
  });
  it("tolerates an empty array", () => {
    expect(gitleaks.parse("[]", "/repo")).toEqual([]);
  });
});

describe("osv-scanner adapter", () => {
  const f = osvScanner.parse(fix("osv-scanner.json"), "/repo");
  it("derives severity from groups.max_severity and pulls cwe + fix", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("high"); // 7.2 → high
    expect(f[0]!.cwe).toBe("CWE-77");
    expect(f[0]!.message).toContain("4.17.21");
    expect(f[0]!.references).toContain("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
  });
});

describe("semgrep / opengrep adapters", () => {
  it("maps ERROR→high, sets file/line and parses CWE from metadata", () => {
    const f = semgrep.parse(fix("semgrep.json"), "/repo");
    expect(f).toHaveLength(1);
    expect(f[0]!.category).toBe("sast");
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.cwe).toBe("CWE-78");
    expect(f[0]!.sink).toEqual({ file: "src/app.py", line: 42 });
  });
  it("opengrep shares the schema", () => {
    const f = opengrep.parse(fix("semgrep.json"), "/repo");
    expect(f[0]!.tool).toBe("opengrep");
    expect(f[0]!.severity).toBe("high");
  });
});

describe("cargo-audit adapter", () => {
  const f = cargoAudit.parse(fix("cargo-audit.json"), "/repo");
  it("emits the vulnerability with CVSS-derived severity + an unmaintained warning", () => {
    const vuln = f.find((x) => x.title.includes("segfault"))!;
    expect(vuln.severity).toBe("medium"); // CVSS:3.1/.../A:H → ~6.2
    expect(vuln.message).toContain("0.2.23");
    const warn = f.find((x) => x.title.includes("Unmaintained"))!;
    expect(warn.severity).toBe("low");
  });
});

describe("govulncheck adapter", () => {
  const f = govulncheck.parse(fix("govulncheck.txt"), "/repo");
  it("correlates finding↔osv, marks reachable high, and locates the call site", () => {
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("high");
    expect(f[0]!.confidence).toBe("high");
    expect(f[0]!.sink).toEqual({ file: "/home/user/proj/main.go", line: 27 });
    expect(f[0]!.message).toContain("v1.20.5");
  });
});

describe("cvss helpers", () => {
  it("computes a v3.1 base score and buckets it", () => {
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(scoreToSeverity(9.8)).toBe("critical");
    expect(deriveSeverity("HIGH")).toBe("high");
    expect(deriveSeverity("7.2")).toBe("high");
    expect(deriveSeverity(null)).toBe("medium");
  });
});

describe("parseJsonStream", () => {
  it("splits concatenated JSON objects", () => {
    const msgs = parseJsonStream('{"a":1}\n{"b":{"c":2}}  {"d":[1,2]}');
    expect(msgs).toHaveLength(3);
  });
  it("skips malformed fragments", () => {
    expect(parseJsonStream("{bad} {\"ok\":1}").length).toBe(1);
  });
});
