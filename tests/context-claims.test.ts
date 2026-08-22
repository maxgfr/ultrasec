import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractNegativeClaims, contradictedClaims } from "../src/context.js";
import { check } from "../src/check.js";
import type { Dossier } from "../src/store.js";
import { SCHEMA_VERSION, VERSION } from "../src/types.js";

// CONTEXT.md is injected into every dossier and every worklist, and until now
// nothing compared a word of it to the code.
//
// One sentence was enough to lose a class. A real audit's CONTEXT.md said "le
// dépôt ne contient aucun `dangerouslySetInnerHTML` en code de production".
// There were eight, in production components. Every later stage read that as
// background, and the stored-XSS family went unexamined — not because the engine
// missed the sinks, but because the auditor had told themselves there were none.
//
// The sentences below are verbatim from the two audited repositories: the one
// that was false, and the ones that were true and must stay quiet.

const FALSE_CLAIM = "- React échappe le JSX par défaut ; le dépôt ne contient aucun `dangerouslySetInnerHTML` en\n  code de production.";

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-claims-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return dir;
}

describe("extractNegativeClaims", () => {
  it("finds the negation and the identifier it is about", () => {
    const claims = extractNegativeClaims(FALSE_CLAIM);
    expect(claims).toHaveLength(1);
    expect(claims[0]!.tokens).toEqual(["dangerouslySetInnerHTML"]);
    // The line the TOKEN is on, not the paragraph's first line.
    expect(claims[0]!.line).toBe(1);
  });

  it("reads a claim wrapped across two lines as one sentence", () => {
    const claims = extractNegativeClaims("Le frontend n'a aucun\n`middleware.ts` global.");
    expect(claims[0]?.tokens).toEqual(["middleware.ts"]);
    expect(claims[0]!.line).toBe(2);
  });

  it("covers English negations too", () => {
    expect(extractNegativeClaims("There is no `dangerouslySetInnerHTML` in this repo.")[0]?.tokens).toEqual(["dangerouslySetInnerHTML"]);
    expect(extractNegativeClaims("The service never calls `child_process`.")[0]?.tokens).toEqual(["child_process"]);
  });

  // ── The false positives that would make this check useless ────────────────

  it("does NOT read a claim about BEHAVIOUR as a claim about presence", () => {
    // Verbatim. React not protecting `dangerouslySetInnerHTML` says nothing
    // about whether the repo contains one, and bare `pas` is excluded for this.
    const md = "React 19 : bloque les URL `javascript:` sur les props JSX `href` (PAS sur\n`dangerouslySetInnerHTML`) ; échappe le texte.";
    expect(extractNegativeClaims(md)).toHaveLength(0);
  });

  it("does NOT claim a token is absent when it is only the LOCATION of an absence", () => {
    // Verbatim. What is missing is the CSRF protection; `pages/api` is where.
    const md = "- Next.js Pages Router : pas de protection CSRF sur les routes `pages/api`.";
    expect(extractNegativeClaims(md)).toHaveLength(0);

    const md2 = "Pas d'échappement automatique pour ce qu'un handler écrit via `res.write`.";
    expect(extractNegativeClaims(md2)).toHaveLength(0);
  });

  it("ignores a code span that is prose or a command, not a name", () => {
    expect(extractNegativeClaims("Aucun rôle anonyme : les métadonnées ne contiennent que `role: super`.")).toHaveLength(0);
    expect(extractNegativeClaims("No `id` is exposed.")).toHaveLength(0); // under the length floor
  });

  it("says nothing about a negation that names nothing checkable", () => {
    // Verbatim, and true. Without an identifier there is nothing to confront.
    expect(extractNegativeClaims("Aucune authentification utilisateur, aucun compte, aucune donnée personnelle.")).toHaveLength(0);
  });
});

describe("contradictedClaims", () => {
  const claims = extractNegativeClaims(FALSE_CLAIM);

  it("reports the occurrences the sentence says do not exist", () => {
    const repo = repoWith({
      "src/Form.tsx": "export const F = () => <div dangerouslySetInnerHTML={{ __html: v }} />;\n",
      "src/Other.tsx": "const a = 1;\nexport const O = () => <p dangerouslySetInnerHTML={{ __html: w }} />;\n",
    });
    const out = contradictedClaims(repo, claims);
    expect(out).toHaveLength(1);
    expect(out[0]!.token).toBe("dangerouslySetInnerHTML");
    expect(out[0]!.total).toBe(2);
    expect(out[0]!.hits.map((h) => `${h.file}:${h.line}`).sort()).toEqual(["src/Form.tsx:1", "src/Other.tsx:2"]);
  });

  it("stays silent when the negation is TRUE", () => {
    const repo = repoWith({ "src/Form.tsx": "export const F = () => <div>{v}</div>;\n" });
    expect(contradictedClaims(repo, claims)).toHaveLength(0);
  });

  it("does not count PROSE about a token as the token", () => {
    // A repo that documents its own worries would otherwise be the loudest.
    const repo = repoWith({
      "AUDIT.md": "We checked every `dangerouslySetInnerHTML` and found none.\n",
      "README.md": "Never use dangerouslySetInnerHTML.\n",
      "src/ok.tsx": "export const F = () => <div>{v}</div>;\n",
    });
    expect(contradictedClaims(repo, claims)).toHaveLength(0);
  });

  it("does not count vendored trees", () => {
    const repo = repoWith({
      "node_modules/react-dom/index.js": "exports.dangerouslySetInnerHTML = 1;\n",
      "src/ok.tsx": "export const F = () => <div>{v}</div>;\n",
    });
    expect(contradictedClaims(repo, claims)).toHaveLength(0);
  });
});

describe("check reports contradictions, and --semantic fails on them", () => {
  const dossier = (repo: string): Dossier => ({
    manifest: {
      version: VERSION,
      schemaVersion: SCHEMA_VERSION,
      repo,
      generatedNote: "",
      languages: ["javascript"],
      toolsRun: [],
      counts: { findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings: [],
    graph: { files: [], edges: [], symbolDefs: {} },
  });

  const seed = (): { repo: string; run: string } => {
    const repo = repoWith({ "src/Form.tsx": "export const F = () => <div dangerouslySetInnerHTML={{ __html: v }} />;\n" });
    const run = mkdtempSync(join(tmpdir(), "ultrasec-claims-run-"));
    writeFileSync(join(run, "CONTEXT.md"), FALSE_CLAIM);
    return { repo, run };
  };

  it("reports without failing the default gate", () => {
    const { repo, run } = seed();
    const res = check(dossier(repo), { repo, run });
    expect(res.contradictions).toHaveLength(1);
    expect(res.contradictions[0]!.token).toBe("dangerouslySetInnerHTML");
    // Prose is not a citation; the grounding gate stays green.
    expect(res.ok).toBe(true);
    // …and no "✓"-prefixed message claims otherwise.
    expect(res.messages.join("\n")).not.toContain("CONTEXT.md");
  });

  it("fails --semantic, and says why", () => {
    const { repo, run } = seed();
    const res = check(dossier(repo), { repo, run, semantic: true });
    expect(res.ok).toBe(false);
    expect(res.messages.join("\n")).toMatch(/negation\(s\) in CONTEXT\.md contradicted/);
  });

  it("is byte-identical to before when there is no CONTEXT.md", () => {
    const { repo } = seed();
    const withoutRun = check(dossier(repo), { repo });
    const emptyRun = check(dossier(repo), { repo, run: mkdtempSync(join(tmpdir(), "ultrasec-claims-empty-")) });
    expect(withoutRun.contradictions).toEqual([]);
    expect(emptyRun.contradictions).toEqual([]);
    expect(emptyRun.messages).toEqual(withoutRun.messages);
    expect(emptyRun.ok).toBe(true);
  });
});
