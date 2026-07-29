import { describe, it, expect } from "vitest";
import { getPrompt, PROMPTS, PromptError, unknownToolNamesIn, toolNamesReferencedBy } from "../src/mcp/prompts.js";

describe("prompt declarations", () => {
  it("names every prompt uniquely and describes what it is for", () => {
    const names = PROMPTS.map((p) => p.name);
    expect(new Set(names).size).toBe(names.length);
    for (const p of PROMPTS) {
      expect(p.name, p.name).toMatch(/^[a-z][a-z0-9_]*$/);
      expect(p.title, p.name).toBeTruthy();
      expect(p.description.length, p.name).toBeGreaterThan(60);
    }
  });

  it("documents every argument", () => {
    for (const p of PROMPTS) {
      for (const a of p.arguments) {
        expect(a.description, `${p.name}.${a.name}`).toBeTruthy();
        expect(a.name, `${p.name}.${a.name}`).toMatch(/^[a-z][a-z0-9_]*$/);
      }
    }
  });
});

describe("prompts/get", () => {
  const args = { repo: "/srv/app", id: "F-1234" };

  it("renders every prompt from its required arguments", () => {
    for (const p of PROMPTS) {
      const got = getPrompt(p.name, args);
      expect(got.description, p.name).toBe(p.description);
      expect(got.messages.length, p.name).toBeGreaterThan(0);
      expect(got.messages[0]!.role, p.name).toBe("user");
      expect(got.messages[0]!.content.type, p.name).toBe("text");
      expect(got.messages[0]!.content.text.length, p.name).toBeGreaterThan(400);
    }
  });

  it("interpolates the arguments it was given", () => {
    const text = getPrompt("judge_finding", args).messages[0]!.content.text;
    expect(text).toContain("/srv/app");
    expect(text).toContain("F-1234");
  });

  it("mentions optional arguments only when they are supplied", () => {
    const without = getPrompt("audit_repo", args).messages[0]!.content.text;
    expect(without).not.toContain("scope:");

    const scoped = getPrompt("audit_repo", { ...args, scope: "packages/api" }).messages[0]!.content.text;
    expect(scoped).toContain("packages/api");
  });

  it("rejects an unknown prompt", () => {
    expect(() => getPrompt("nope", args)).toThrow(PromptError);
  });

  it("rejects a missing required argument", () => {
    expect(() => getPrompt("judge_finding", { repo: "/srv/app" })).toThrow(/`id` is required/);
    expect(() => getPrompt("audit_repo", {})).toThrow(/`repo` is required/);
    // Whitespace is not an argument.
    expect(() => getPrompt("audit_repo", { repo: "   " })).toThrow(/`repo` is required/);
  });
});

describe("prompts stay honest about the tools", () => {
  const args = { repo: "/srv/app", id: "F-1234" };

  it("never tells the model to call a tool that is not declared", () => {
    // The failure this catches: a tool gets renamed, the prompt keeps naming
    // the old one, and every host following the prompt fails on a tool that
    // does not exist. Nobody notices, because the prompt still reads fine.
    for (const p of PROMPTS) {
      const text = getPrompt(p.name, args).messages[0]!.content.text;
      expect(unknownToolNamesIn(text), `${p.name} names undeclared tools`).toEqual([]);
    }
  });

  it("gives each workflow a real tool sequence, ending at the citation gate", () => {
    for (const p of PROMPTS) {
      const text = getPrompt(p.name, args).messages[0]!.content.text;
      const referenced = toolNamesReferencedBy(text);
      expect(referenced.length, `${p.name} names no tools at all`).toBeGreaterThan(2);
      expect(referenced, `${p.name} never reaches the gate`).toContain("ultrasec_check");
    }
  });

  it("carries the core rule into every workflow", () => {
    // Every prompt must state the do-not-answer-from-memory rule. A workflow
    // that lists tools without it is the failure mode this whole primitive
    // exists to prevent.
    for (const p of PROMPTS) {
      const text = getPrompt(p.name, args).messages[0]!.content.text;
      expect(text, p.name).toContain("The engine finds CANDIDATES; you decide");
      expect(text, p.name).toMatch(/\[file:line\]/);
    }
  });
});
