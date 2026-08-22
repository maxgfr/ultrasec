import { describe, it, expect } from "vitest";
import { findSinks, findTextSinks, findSanitizers, SINKS, TEXT_SINKS } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import type { Call } from "../src/lang.js";

// Two classes an audit of a real repository found by hand and the engine could
// not enumerate at all. Every literal below is a line copied out of the audited
// source, so a regression here is a regression against ground truth, not
// against an invented shape.
//
//   CWE-407 — `packages/code-du-travail-frontend/src/api/modules/search/
//             service/prequalified.ts:101`  (audit finding A2, rated HIGH)
//   CWE-209 — `.../api/modules/enterprises/controller.ts:50`
//             `.../api/modules/accords/controller.ts:30`  (audit finding A12)

const JS = langForFile("x.ts")!;
const PY = langForFile("x.py")!;

const call = (callee: string, receiver?: string, line = 1): Call => ({ callee, receiver, line });

describe("CWE-407 — algorithmic DoS on a library call", () => {
  const fuzzballImport = [{ spec: "fuzzball" }];

  it("fires on `fuzz.extract()` in a file that imports fuzzball", () => {
    const hits = findSinks(JS, [call("extract", "fuzz", 101)], undefined, fuzzballImport);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.kind).toBe("algodos");
    expect(hits[0]!.cwe).toBe("CWE-407");
    expect(hits[0]!.severity).toBe("medium");
    // Corroborated by the import, so it is NOT the downgraded shape.
    expect(hits[0]!.downgraded).toBeUndefined();
  });

  it("does NOT fire on the same call in a file that imports something else", () => {
    // `extract` is an ordinary method name. Without the module, an `ambiguous`
    // rule must stay silent when imports were actually visible.
    const hits = findSinks(JS, [call("extract", "archive", 12)], undefined, [{ spec: "tar-fs" }]);
    expect(hits.filter((h) => h.kind === "algodos")).toHaveLength(0);
  });

  it("keeps the hit, downgraded, when no imports could be extracted at all", () => {
    // The regex tier sees no imports. A critical we cannot substantiate is worse
    // than a medium we can revisit — same trade `exec` makes.
    const hits = findSinks(JS, [call("extract", "fuzz", 101)], undefined, []);
    const algo = hits.find((h) => h.kind === "algodos");
    expect(algo, "expected the uncorroborated hit to survive, downgraded").toBeTruthy();
    expect(algo!.downgraded).toBeTruthy();
  });

  it("covers python's difflib/rapidfuzz shape", () => {
    const hits = findSinks(PY, [call("get_close_matches", "difflib", 7)], undefined, [{ spec: "difflib" }]);
    expect(hits.map((h) => h.kind)).toContain("algodos");
  });

  it("recognises an upper bound as the sanitizer, and a MINIMUM as nothing", () => {
    // The audited repo's only guard was `query.length >= 3` — a floor, which
    // bounds nothing. The fix it needed was `z.string().max(200)`.
    expect(findSanitizers(JS, "const ppQuery = preprocess(query.slice(0, 200));", "algodos")).not.toHaveLength(0);
    expect(findSanitizers(JS, "  q: z.string().min(1),", "algodos")).toHaveLength(0);
  });

  it("is declared before the rules that also claim these callee names", () => {
    // `findSinks` breaks on the first matching rule, so ordering is behaviour.
    const kinds = SINKS.map((r) => r.kind);
    expect(kinds).toContain("algodos");
  });
});

describe("CWE-209 — the caught error handed back to the caller", () => {
  const hit = (line: string, lang = JS) => findTextSinks(lang, line).find((h) => h.kind === "errleak");

  it("matches the two audited lines verbatim", () => {
    const a = hit(`      return NextResponse.json({ message: String(error) }, { status: 500 });`);
    expect(a, "enterprises/controller.ts:50").toBeTruthy();
    expect(a!.cwe).toBe("CWE-209");
    expect(a!.severity).toBe("low");
    expect(a!.callee).toBe("error → response body");
  });

  it("matches the express `res.status(500).json({ error: err.message })` shape", () => {
    expect(hit(`    res.status(500).json({ error: err.message });`)).toBeTruthy();
    expect(hit(`  res.send(e.stack);`)).toBeTruthy();
    // Built by concatenation so the linter does not read the fixture's own
    // template placeholder as an unintended interpolation in THIS file.
    expect(hit("  reply.send(`failed: $" + "{error}`);")).toBeTruthy();
  });

  it("does NOT match a response that carries no error detail", () => {
    expect(hit(`  return res.json({ ok: true });`)).toBeFalsy();
    expect(hit(`  res.status(500).json({ message: "Internal error" });`)).toBeFalsy();
  });

  it("does NOT match two unrelated statements that share a line", () => {
    // The gap between the writer and the error expression forbids `)`, so a
    // completed call followed by a log on the same line cannot match.
    expect(hit(`  const d = await res.json(); logger.error(err.message);`)).toBeFalsy();
  });

  it("covers the flask/django shape", () => {
    expect(hit(`        return jsonify({"error": str(e)}), 500`, PY)).toBeTruthy();
    expect(hit(`    return JsonResponse({"detail": traceback.format_exc()}, status=500)`, PY)).toBeTruthy();
    expect(hit(`    return jsonify({"error": "internal"}), 500`, PY)).toBeFalsy();
  });

  it("keeps every errleak rule out of the constant-value gate", () => {
    // `requiresDynamicValue` reads the text after an `=`; these rules match a
    // CALL, so setting it would make them read the wrong half of the line.
    for (const r of TEXT_SINKS.filter((r) => r.kind === "errleak")) {
      expect(r.requiresDynamicValue).toBeUndefined();
    }
  });
});
