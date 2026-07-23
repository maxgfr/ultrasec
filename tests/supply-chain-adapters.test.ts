import { describe, it, expect } from "vitest";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { grype } from "../src/tools/grype.js";
import { pipAudit } from "../src/tools/pip-audit.js";

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
