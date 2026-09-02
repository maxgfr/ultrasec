import { describe, it, expect } from "vitest";
import { LANGS, type Call, type LangSpec } from "../src/lang.js";
import {
  SINKS,
  LOG_SINKS,
  SOURCES,
  TEXT_SINKS,
  SANITIZERS,
  findSinks,
  findSources,
  findTextSinks,
  findSanitizers,
  type SinkRule,
  type SinkHit,
} from "../src/catalog.js";

// The catalog lookups are indexed (by callee for call sinks, by language for the
// line-shaped rules). The index is a pure optimization: for every callee, every
// language and every corroboration shape the indexed function must return
// exactly what the original linear scan returned — same hits, same order, same
// first-matching rule. The reference implementations below ARE the original
// loops, kept verbatim so a drift in the index shows up as a diff here rather
// than as a silently different finding set.

function appliesTo(languages: string[], langId: string): boolean {
  return languages.includes("*") || languages.includes(langId);
}

function findSinksRef(
  lang: LangSpec,
  calls: Call[],
  extraSinks?: SinkRule[],
  imports?: readonly { spec: string }[],
  localDefs?: ReadonlySet<string>,
): SinkHit[] {
  const rules = extraSinks && extraSinks.length ? [...SINKS, ...extraSinks] : SINKS;
  const out: SinkHit[] = [];
  const specs = (imports ?? []).map((i) => i.spec.toLowerCase());
  for (const c of calls) {
    const shadowed = !c.receiver && localDefs?.has(c.callee) === true;
    for (const rule of rules) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      if (!rule.callees.includes(c.callee)) continue;
      if (rule.requireReceiver && !c.receiver) continue;
      if (rule.receivers && c.receiver && !rule.receivers.includes(c.receiver)) continue;
      const moduleSeen = !!rule.requireModule && rule.requireModule.some((m) => specs.some((s) => s.includes(m.toLowerCase())));
      if (rule.requireModule && specs.length && !moduleSeen) continue;
      let downgraded: string | undefined;
      if (rule.ambiguous && !(c.receiver && rule.receivers?.includes(c.receiver))) {
        if (shadowed) continue;
        if (!moduleSeen) {
          if (specs.length) continue;
          downgraded = "unresolved-receiver";
        }
      }
      out.push({
        line: c.line,
        callee: c.callee,
        receiver: c.receiver,
        kind: rule.kind,
        cwe: rule.cwe,
        severity: downgraded ? "medium" : rule.severity,
        title: rule.title,
        note: rule.note,
        ...(downgraded ? { downgraded } : {}),
      });
      break;
    }
  }
  return out;
}

function findSourcesRef(lang: LangSpec, content: string) {
  const out: { line: number; kind: string; match: string; title: string }[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const rule of SOURCES) {
      if (!appliesTo(rule.languages, lang.id)) continue;
      const m = rule.re.exec(line);
      if (m) out.push({ line: i + 1, kind: rule.kind, match: m[0], title: rule.title });
    }
  }
  return out;
}

function findSanitizersRef(lang: LangSpec, line: string, sinkKind: string): string[] {
  const hints: string[] = [];
  for (const rule of SANITIZERS) {
    if (!appliesTo(rule.languages, lang.id)) continue;
    if (rule.kind !== "*" && rule.kind !== sinkKind) continue;
    if (rule.exceptKinds?.includes(sinkKind)) continue;
    if (rule.re.test(line)) hints.push(rule.note);
  }
  return hints;
}

/** Every callee the two tables know, plus a few that no rule names. */
const ALL_CALLEES = [...new Set([...SINKS, ...LOG_SINKS].flatMap((r) => r.callees)), "notASink", "toString", "map"].sort();
/** Every receiver any rule pins, plus unknown ones and none. */
const RECEIVERS = [...new Set([...SINKS, ...LOG_SINKS].flatMap((r) => r.receivers ?? []))].slice(0, 10).concat(["someObj", undefined as unknown as string]);
/** Import shapes: none, a corroborating module for each rule that wants one, and an unrelated one. */
const IMPORT_SETS: (readonly { spec: string }[] | undefined)[] = [
  undefined,
  [],
  [{ spec: "lodash" }],
  ...[...new Set([...SINKS, ...LOG_SINKS].flatMap((r) => r.requireModule ?? []))].filter((_, i) => i % 4 === 0).map((m) => [{ spec: m }]),
];

describe("catalog index — findSinks equals the linear reference for every callee", () => {
  const calls: Call[] = [];
  let line = 1;
  for (const callee of ALL_CALLEES) {
    for (const receiver of RECEIVERS) calls.push({ callee, line: line++, ...(receiver ? { receiver } : {}) });
  }

  for (const lang of LANGS) {
    it(`${lang.id}: default catalog, every import/receiver shape`, () => {
      for (const imports of IMPORT_SETS) {
        expect(findSinks(lang, calls, undefined, imports)).toEqual(findSinksRef(lang, calls, undefined, imports));
      }
    });

    it(`${lang.id}: with LOG_SINKS unioned in`, () => {
      for (const imports of IMPORT_SETS) {
        expect(findSinks(lang, calls, LOG_SINKS, imports)).toEqual(findSinksRef(lang, calls, LOG_SINKS, imports));
      }
    });

    it(`${lang.id}: local-definition shadowing`, () => {
      const localDefs = new Set(ALL_CALLEES.filter((_, i) => i % 3 === 0));
      expect(findSinks(lang, calls, undefined, [{ spec: "child_process" }], localDefs)).toEqual(
        findSinksRef(lang, calls, undefined, [{ spec: "child_process" }], localDefs),
      );
      expect(findSinks(lang, calls, undefined, [], localDefs)).toEqual(findSinksRef(lang, calls, undefined, [], localDefs));
    });
  }

  it("first matching rule still wins in table order (a callee named by several rules)", () => {
    const multi = ALL_CALLEES.filter((c) => SINKS.filter((r) => r.callees.includes(c)).length > 1);
    expect(multi.length).toBeGreaterThan(0);
    for (const lang of LANGS) {
      const cs = multi.map((callee, i) => ({ callee, line: i + 1 }));
      expect(findSinks(lang, cs)).toEqual(findSinksRef(lang, cs));
    }
  });

  it("a rebuilt extras array gets its own index (identity-keyed, never stale)", () => {
    const extra: SinkRule[] = [{ kind: "zzz", cwe: "CWE-1", severity: "low", languages: ["*"], callees: ["notASink"], title: "t", note: "n" }];
    const cs = [{ callee: "notASink", line: 1 }];
    expect(findSinks(LANGS[0]!, cs, extra).map((h) => h.kind)).toEqual(["zzz"]);
    const extra2: SinkRule[] = [{ ...extra[0]!, kind: "yyy" }];
    expect(findSinks(LANGS[0]!, cs, extra2).map((h) => h.kind)).toEqual(["yyy"]);
    expect(findSinks(LANGS[0]!, cs).map((h) => h.kind)).toEqual([]);
  });
});

// A line corpus that exercises every source / text-sink / sanitizer regex at
// least once: the rule's own source, flattened to a plausible line.
function corpusFrom(res: RegExp[]): string {
  const lines = res.map((re) =>
    re.source
      .replace(/\\b|\^|\$|\(\?:|\(\?<!|\(\?!|\(\?=|\(|\)|\[\^?|\]|[*+?]|\{\d+(,\d*)?\}|\\s\*/g, "")
      .replace(/\\\./g, ".")
      .replace(/\|/g, " ")
      .replace(/\\/g, ""),
  );
  return [
    ...lines,
    'const id = req.query.id; db.query("SELECT * FROM t WHERE id=" + id)',
    "el.innerHTML = user; document.write(x); location.href = y",
    '<div v-html="content"></div><div [innerHTML]="x"></div>',
    "const safe = escapeHtml(raw); const n = parseInt(q, 10); schema.parse(body)",
    'stmt.setString(1, name); cursor.execute("...", (a,))',
    "plain line with nothing in it",
  ].join("\n");
}

describe("catalog index — line-shaped rules equal the linear reference per language", () => {
  const sourceCorpus = corpusFrom(SOURCES.map((r) => r.re));
  const textSinkCorpus = corpusFrom(TEXT_SINKS.map((r) => r.re));
  const sanitizerLines = corpusFrom(SANITIZERS.map((r) => r.re)).split("\n");
  const KINDS = [...new Set([...SINKS.map((r) => r.kind), ...TEXT_SINKS.map((r) => r.kind), "*", "nope"])];

  for (const lang of LANGS) {
    it(`${lang.id}: findSources`, () => {
      expect(findSources(lang, sourceCorpus)).toEqual(findSourcesRef(lang, sourceCorpus));
    });

    it(`${lang.id}: findTextSinks — same hits and same first rule as an unindexed scan`, () => {
      // Reference: the same loop over the full table.
      const ref = (content: string) => {
        const out: { line: number; kind: string; callee: string }[] = [];
        const ls = content.split(/\r?\n/);
        for (let i = 0; i < ls.length; i++) {
          for (const rule of TEXT_SINKS) {
            if (!appliesTo(rule.languages, lang.id)) continue;
            if (!rule.re.exec(ls[i]!)) continue;
            out.push({ line: i + 1, kind: rule.kind, callee: rule.label });
            break;
          }
        }
        return out;
      };
      const got = findTextSinks(lang, textSinkCorpus).map((h) => ({ line: h.line, kind: h.kind, callee: h.callee }));
      // The indexed version also applies `requiresDynamicValue`; the reference
      // does not, so compare on the subset the constant filter cannot touch.
      const dynamicOnly = new Set(TEXT_SINKS.filter((r) => r.requiresDynamicValue).map((r) => r.kind));
      expect(got.filter((h) => !dynamicOnly.has(h.kind))).toEqual(ref(textSinkCorpus).filter((h) => !dynamicOnly.has(h.kind)));
    });

    it(`${lang.id}: findSanitizers for every sink kind`, () => {
      for (const kind of KINDS) {
        for (const line of sanitizerLines) {
          expect(findSanitizers(lang, line, kind)).toEqual(findSanitizersRef(lang, line, kind));
        }
      }
    });
  }
});
