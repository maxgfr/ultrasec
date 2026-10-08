import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mergeDossier, countBySeverity, type Dossier } from "../src/store.js";
import { runScan } from "../src/commands/scan.js";
import { parseArgs } from "../src/util.js";
import type { Finding, Manifest } from "../src/types.js";
import type { Graph } from "../src/graph.js";

const emptyGraph = (files: string[] = []): Graph => ({ files, edges: [], symbolDefs: {}, callersBySymbol: {} });

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    category: "taint",
    title: `finding ${id}`,
    severity: "high",
    confidence: "low",
    message: "candidate",
    tool: "ultrasec",
    status: "open",
    ...over,
  };
}

function dossier(findings: Finding[], scopes?: string[]): Dossier {
  const manifest: Manifest = {
    version: "x",
    schemaVersion: 2,
    repo: "/r",
    generatedNote: "",
    languages: ["javascript"],
    toolsRun: [],
    counts: { findings: findings.length, bySeverity: countBySeverity(findings) },
    ...(scopes ? { scopes } : {}),
  };
  return { manifest, findings, graph: emptyGraph(findings.flatMap((f) => (f.sink ? [f.sink.file] : []))) };
}

describe("mergeDossier", () => {
  it("preserves a confirmed verdict across a scoped re-scan", () => {
    const prev = dossier([
      finding("a", { status: "confirmed", verdict: "supported", confidence: "high", exploitPath: "GET /x", message: "candidate\n\nVerdict (supported): real" }),
    ]);
    // the same finding re-enumerated by a scoped pass arrives as fresh `open`
    const next = dossier([finding("a", { status: "open", confidence: "low", message: "candidate" })], ["src"]);
    const merged = mergeDossier(prev, next);
    const a = merged.findings.find((f) => f.id === "a")!;
    expect(a.status).toBe("confirmed");
    expect(a.verdict).toBe("supported");
    expect(a.exploitPath).toBe("GET /x");
    expect(a.message).toContain("Verdict (supported)");
  });

  it("preserves the refutation ground and the fix commit across a re-scan", () => {
    // Both were missing from the preserve-list, so a `scan --merge` erased every
    // named ground — after which `check --semantic` reported those dismissals as
    // naming no ground, blaming the auditor for the tool's own data loss.
    const prev = dossier([finding("a", { status: "dismissed", verdict: "refuted", brocard: "outside-usage", fixedIn: "abc1234" })]);
    const next = dossier([finding("a", { status: "open" })], ["src"]);
    const a = mergeDossier(prev, next).findings.find((f) => f.id === "a")!;
    expect(a.brocard).toBe("outside-usage");
    expect(a.fixedIn).toBe("abc1234");
  });

  it("does not invent a brocard on a finding that never had one", () => {
    const prev = dossier([finding("a", { status: "dismissed", verdict: "refuted" })]);
    const next = dossier([finding("a", { status: "open" })], ["src"]);
    const a = mergeDossier(prev, next).findings.find((f) => f.id === "a")!;
    expect(a.brocard).toBeUndefined();
    expect("brocard" in a).toBe(false);
  });

  it("appends genuinely new findings", () => {
    const prev = dossier([finding("a")]);
    const next = dossier([finding("b", { severity: "critical" })], ["src/api"]);
    const merged = mergeDossier(prev, next);
    expect(merged.findings.map((f) => f.id).sort()).toEqual(["a", "b"]);
    expect(merged.manifest.counts.findings).toBe(2);
  });

  it("keeps findings outside the current pass's scope (does not delete them)", () => {
    const prev = dossier([finding("a", { status: "confirmed" }), finding("b", { status: "dismissed" })]);
    const next = dossier([finding("a", { status: "open" })], ["src"]); // only re-scanned 'a'
    const merged = mergeDossier(prev, next);
    expect(merged.findings.map((f) => f.id).sort()).toEqual(["a", "b"]); // 'b' survives
    expect(merged.findings.find((f) => f.id === "b")!.status).toBe("dismissed");
  });

  it("a SCOPED merge carries a prior cap forward (must not hide a capped run)", () => {
    const prev = dossier([finding("a")]);
    prev.manifest.truncation = { candidates: 3400, total: 4400 };
    const next = dossier([finding("a")], ["src"]); // scoped pass, NOT truncated
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.truncation).toBeTruthy();
    expect(merged.manifest.truncation!.candidates).toBe(3400);
    expect(merged.manifest.truncation!.total).toBe(4400);
  });

  it("a FULL uncapped re-scan CLEARS a stale prior cap (no false truncation warning)", () => {
    const prev = dossier([finding("a")]);
    prev.manifest.truncation = { candidates: 3400, total: 4400 };
    const next = dossier([finding("a")]); // full re-scan (no scopes), not truncated
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.truncation).toBeUndefined(); // stale cap cleared
  });

  it("unions scopes and is idempotent", () => {
    const prev = dossier([finding("a")], ["src"]);
    const next = dossier([finding("a")], ["lib"]);
    const merged = mergeDossier(prev, next);
    expect(merged.manifest.scopes).toEqual(["lib", "src"]);
    expect(mergeDossier(merged, merged).findings).toEqual(merged.findings);
  });

  describe("a re-detected finding takes the engine's fresh message", () => {
    // On a real run the committed-hash detector was fixed to mask the hash it
    // quotes, `scan --merge` re-detected the same finding under the same id, and
    // the merge kept the OLD message — full argon2 hash and all — so the leak
    // outlived the fix. The verdicts were in that message too, which is why it
    // was kept; only they are the auditor's.
    const salt = "c2FsdHNhbHRzYWx0";
    const digest = "ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0";
    const argon = ["$argon2id", "v=19", "m=65536,t=3,p=4", salt, digest].join("$");
    const masked = "$argon2id$v=19$m=65536,t=3,p=4$…";

    it("drops the stale evidence and keeps the verdict and revalidation notes", () => {
      const prev = dossier([
        finding("a", {
          status: "confirmed",
          verdict: "supported",
          message: `A seed creates an account.\n\nEvidence: \`'${argon}'\`\n\nVerdict (supported): seeded on every preprod restore\n\nRevalidation (still-valid): still at HEAD`,
        }),
      ]);
      const next = dossier([finding("a", { message: `A seed creates an account.\n\nEvidence: \`'${masked}'\`` })]);
      const a = mergeDossier(prev, next).findings.find((f) => f.id === "a")!;
      expect(a.message).toBe(
        `A seed creates an account.\n\nEvidence: \`'${masked}'\`\n\nVerdict (supported): seeded on every preprod restore\n\nRevalidation (still-valid): still at HEAD`,
      );
      expect(a.message).not.toContain(digest);
      expect(a.status).toBe("confirmed");
    });

    it("redacts a carried note written before notes were redacted", () => {
      // The second leak of the same run: the revalidator quoted the cited line.
      const prev = dossier([finding("a", { status: "confirmed", message: `old\n\nRevalidation (still-valid): line is ('admin', '${argon}', 'owner')` })]);
      const a = mergeDossier(prev, dossier([finding("a", { message: "fresh" })])).findings[0]!;
      expect(a.message).toBe(`fresh\n\nRevalidation (still-valid): line is ('admin', '${masked}', 'owner')`);
    });

    it("carries a triage dismissal, which is not a labelled stage block", () => {
      const prev = dossier([finding("a", { status: "dismissed", severity: "low", message: "old prose\n\nTriage: dismissed as noise." })]);
      const a = mergeDossier(prev, dossier([finding("a", { severity: "low", message: "new prose" })])).findings[0]!;
      expect(a.message).toBe("new prose\n\nTriage: dismissed as noise.");
    });

    it("keeps blame provenance when the re-scan ran without --blame", () => {
      const provenance = { commit: "abc1234567", author: "Jane", date: "2023-11-14" };
      const prev = dossier([finding("a", { status: "confirmed", provenance })]);
      const a = mergeDossier(prev, dossier([finding("a")])).findings[0]!;
      expect(a.provenance).toEqual(provenance);
    });

    it("is idempotent once the notes are carried", () => {
      const prev = dossier([finding("a", { status: "confirmed", message: `old ${argon}\n\nVerdict (supported): real ${argon}` })]);
      const merged = mergeDossier(prev, dossier([finding("a", { message: "fresh" })]));
      expect(mergeDossier(merged, merged).findings).toEqual(merged.findings);
    });
  });
});

describe("scan --merge, end to end", () => {
  // The whole incident through the real command: a dossier written by the
  // detector before it masked hashes, adjudicated, then merged into.
  it("re-detects a committed hash with the masked evidence and keeps the verdict", async () => {
    const digest = "ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0";
    const argon = ["$argon2id", "v=19", "m=65536,t=3,p=4", "c2FsdHNhbHRzYWx0", digest].join("$");
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-merge-hash-"));
    writeFileSync(join(repo, "seed.sql"), `INSERT INTO users VALUES ('admin@example.org', '${argon}', 'owner');\n`);
    const out = join(repo, ".ultrasec");
    const scan = (...extra: string[]) => runScan(parseArgs(["scan", "--repo", repo, "--out", out, "--no-enrich", "--no-tools", ...extra]));

    expect(await scan()).toBe(0);
    const findings = JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as import("../src/types.js").Finding[];
    const hit = findings.find((f) => f.cwe === "CWE-798" && f.sink?.file === "seed.sql")!;
    expect(hit).toBeDefined();
    // Rewind it to what the pre-fix detector wrote, then adjudicate it.
    hit.message = `${hit.message.split("\n\nEvidence:")[0]}\n\nEvidence: \`'${argon}'\`\n\nVerdict (supported): seeded on every restore`;
    hit.status = "confirmed";
    hit.verdict = "supported";
    writeFileSync(join(out, "findings.json"), JSON.stringify(findings, null, 2));

    expect(await scan("--merge")).toBe(0);
    const merged = (JSON.parse(readFileSync(join(out, "findings.json"), "utf8")) as typeof findings).find((f) => f.id === hit.id)!;
    expect(merged.status).toBe("confirmed");
    expect(merged.message).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(merged.message).toContain("Verdict (supported): seeded on every restore");
    expect(merged.message).not.toContain(digest);
    expect(readFileSync(join(out, "DOSSIER.md"), "utf8")).not.toContain(digest);
  });
});
