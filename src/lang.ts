// Declarative, tree-sitter-free language registry. Each language is described by
// regexes for definitions, imports and call-sites; extraction is line-oriented
// so every symbol/import/call carries a 1-based line. This is intentionally
// heuristic — it is a *scaffold* for the AI's cross-file reasoning, not a
// compiler. Breadth (~15 languages) beats per-language perfection here.

export type SymbolKind = "function" | "class" | "method" | "struct" | "const";

export interface DefPattern {
  kind: SymbolKind;
  re: RegExp; // capture group 1 = identifier
}

export type ExportRule = "js" | "leadingUnderscore" | "capitalized" | "always";

export interface LangSpec {
  id: string;
  extensions: string[];
  defs: DefPattern[];
  imports: RegExp[]; // capture group 1 = module specifier
  exportRule: ExportRule;
  /** Extra keywords (beyond the shared set) that look like calls but aren't. */
  keywords?: string[];
}

export interface Sym {
  name: string;
  kind: SymbolKind;
  line: number;
  exported: boolean;
}
export interface Imp {
  spec: string;
  line: number;
}
export interface Call {
  callee: string;
  receiver?: string;
  line: number;
}
export interface Extraction {
  symbols: Sym[];
  imports: Imp[];
  calls: Call[];
}

// Control-flow / declaration words that precede `(` but are not function calls.
const SHARED_KEYWORDS = new Set([
  "if", "for", "while", "switch", "catch", "return", "function", "await",
  "typeof", "instanceof", "new", "delete", "void", "in", "of", "do", "else",
  "case", "throw", "with", "super", "this", "and", "or", "not", "is",
]);

const ID = "[A-Za-z_$][\\w$]*";

export const LANGS: LangSpec[] = [
  {
    id: "javascript",
    extensions: ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"],
    defs: [
      { kind: "function", re: new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function\\s*\\*?\\s+(${ID})`) },
      { kind: "function", re: new RegExp(`(?:export\\s+)?(?:const|let|var)\\s+(${ID})\\s*=\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*=>|${ID}\\s*=>)`) },
      { kind: "class", re: new RegExp(`(?:export\\s+)?(?:default\\s+)?(?:abstract\\s+)?class\\s+(${ID})`) },
    ],
    imports: [
      /import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/,
      /require\(\s*['"]([^'"]+)['"]\s*\)/,
      /import\(\s*['"]([^'"]+)['"]\s*\)/,
    ],
    exportRule: "js",
  },
  {
    id: "python",
    extensions: ["py", "pyi"],
    defs: [
      { kind: "function", re: /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/ },
      { kind: "class", re: /^\s*class\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*import\s+([\w.]+)/, /^\s*from\s+([\w.]+)\s+import/],
    exportRule: "leadingUnderscore",
    keywords: ["def", "class", "lambda", "elif", "except", "raise", "yield", "assert", "pass", "global", "nonlocal", "print"],
  },
  {
    id: "go",
    extensions: ["go"],
    defs: [
      { kind: "function", re: /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)/ },
      { kind: "struct", re: /^\s*type\s+([A-Za-z_]\w*)\s+struct/ },
    ],
    imports: [/^\s*"([^"]+)"\s*$/, /import\s+(?:[\w.]+\s+)?"([^"]+)"/],
    exportRule: "capitalized",
    keywords: ["func", "go", "defer", "select", "range", "var", "const", "type", "package", "map", "make", "chan"],
  },
  {
    id: "java",
    extensions: ["java"],
    defs: [
      { kind: "class", re: /(?:class|interface|enum|record)\s+([A-Za-z_]\w*)/ },
      { kind: "method", re: /(?:public|private|protected)\s+(?:static\s+|final\s+|abstract\s+|synchronized\s+|native\s+)*[\w<>\[\].,?\s]+?\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*(?:throws[\w,.\s]+)?\{/ },
    ],
    imports: [/^\s*import\s+(?:static\s+)?([\w.]+)\s*;/],
    exportRule: "always",
    keywords: ["new", "class", "interface", "enum", "extends", "implements", "synchronized", "assert"],
  },
  {
    id: "ruby",
    extensions: ["rb"],
    defs: [
      { kind: "method", re: /^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?]?)/ },
      { kind: "class", re: /^\s*(?:class|module)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/require(?:_relative)?\s+['"]([^'"]+)['"]/],
    exportRule: "always",
    keywords: ["def", "end", "unless", "elsif", "begin", "rescue", "ensure", "yield", "module", "require", "puts", "raise"],
  },
  {
    id: "php",
    extensions: ["php"],
    defs: [
      { kind: "function", re: /function\s+([A-Za-z_]\w*)\s*\(/ },
      { kind: "class", re: /(?:class|trait|interface)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/(?:require|include)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]/, /^\s*use\s+([\w\\]+)/],
    exportRule: "always",
    keywords: ["function", "class", "elseif", "foreach", "endif", "endforeach", "echo", "print", "isset", "empty", "array", "use", "namespace"],
  },
  {
    id: "rust",
    extensions: ["rs"],
    defs: [
      { kind: "function", re: /(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/ },
      { kind: "struct", re: /(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*use\s+([\w:]+)/],
    exportRule: "always",
    keywords: ["fn", "let", "match", "impl", "loop", "mut", "pub", "use", "mod", "struct", "enum", "trait", "unsafe", "move", "as", "ref"],
  },
  {
    id: "c_cpp",
    extensions: ["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx"],
    defs: [
      { kind: "function", re: /^[\w\s\*&:<>,]+?\s+\*?([A-Za-z_]\w*)\s*\([^;]*\)\s*\{/ },
      { kind: "struct", re: /^\s*(?:typedef\s+)?(?:struct|class|enum|union)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*#\s*include\s*[<"]([^>"]+)[>"]/],
    exportRule: "always",
    keywords: ["if", "for", "while", "switch", "return", "sizeof", "struct", "union", "enum", "static", "const", "typedef"],
  },
  {
    id: "csharp",
    extensions: ["cs"],
    defs: [
      { kind: "class", re: /(?:class|interface|struct|record|enum)\s+([A-Za-z_]\w*)/ },
      { kind: "method", re: /(?:public|private|protected|internal)\s+(?:static\s+|virtual\s+|override\s+|async\s+|sealed\s+)*[\w<>\[\].,?\s]+?\s+([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{/ },
    ],
    imports: [/^\s*using\s+(?:static\s+)?([\w.]+)\s*;/],
    exportRule: "always",
    keywords: ["new", "class", "interface", "struct", "using", "namespace", "async", "await", "var"],
  },
  {
    id: "kotlin",
    extensions: ["kt", "kts"],
    defs: [
      { kind: "function", re: /fun\s+(?:<[^>]+>\s+)?(?:[A-Za-z_][\w.]*\.)?([A-Za-z_]\w*)\s*\(/ },
      { kind: "class", re: /(?:class|interface|object|enum class)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["fun", "val", "var", "when", "class", "object", "import", "package", "is", "as", "in"],
  },
  {
    id: "swift",
    extensions: ["swift"],
    defs: [
      { kind: "function", re: /func\s+([A-Za-z_]\w*)\s*[(<]/ },
      { kind: "class", re: /(?:class|struct|enum|protocol|actor)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["func", "let", "var", "guard", "switch", "class", "struct", "enum", "import", "as", "is", "in", "case"],
  },
  {
    id: "scala",
    extensions: ["scala", "sc"],
    defs: [
      { kind: "function", re: /def\s+([A-Za-z_]\w*)/ },
      { kind: "class", re: /(?:class|trait|object|case class)\s+([A-Za-z_]\w*)/ },
    ],
    imports: [/^\s*import\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["def", "val", "var", "match", "class", "trait", "object", "import", "case", "yield", "implicit"],
  },
  {
    id: "shell",
    extensions: ["sh", "bash", "zsh"],
    defs: [
      { kind: "function", re: /^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{/ },
    ],
    imports: [/^\s*(?:source|\.)\s+([^\s;]+)/],
    exportRule: "always",
    keywords: ["if", "then", "fi", "for", "do", "done", "while", "case", "esac", "echo", "function", "return", "local", "export"],
  },
  {
    id: "lua",
    extensions: ["lua"],
    defs: [
      { kind: "function", re: /function\s+(?:[A-Za-z_][\w.:]*\.)?([A-Za-z_]\w*)\s*\(/ },
      { kind: "function", re: /(?:local\s+)?([A-Za-z_]\w*)\s*=\s*function\s*\(/ },
    ],
    imports: [/require\s*\(?\s*['"]([^'"]+)['"]/],
    exportRule: "always",
    keywords: ["function", "local", "end", "then", "elseif", "repeat", "until", "do", "nil", "and", "or", "not", "print"],
  },
  {
    id: "elixir",
    extensions: ["ex", "exs"],
    defs: [
      { kind: "function", re: /^\s*def(?:p)?\s+([A-Za-z_]\w*[!?]?)/ },
      { kind: "class", re: /^\s*defmodule\s+([A-Za-z_][\w.]*)/ },
    ],
    imports: [/^\s*(?:import|alias|require|use)\s+([\w.]+)/],
    exportRule: "always",
    keywords: ["def", "defp", "defmodule", "do", "end", "fn", "case", "cond", "when", "import", "alias", "require", "use"],
  },
];

const byExt = new Map<string, LangSpec>();
for (const l of LANGS) for (const ext of l.extensions) byExt.set(ext, l);

export function langForFile(rel: string): LangSpec | undefined {
  const dot = rel.lastIndexOf(".");
  if (dot < 0) return undefined;
  return byExt.get(rel.slice(dot + 1).toLowerCase());
}

function isExported(rule: ExportRule, name: string, defLine: string, content: string): boolean {
  switch (rule) {
    case "always":
      return true;
    case "leadingUnderscore":
      return !name.startsWith("_");
    case "capitalized":
      return /^[A-Z]/.test(name);
    case "js":
      if (/\bexport\b/.test(defLine)) return true;
      // CJS: module.exports = { name }, exports.name = , module.exports = name
      const reExports = new RegExp(`\\b(?:module\\.)?exports\\b[^\\n]*\\b${name}\\b`);
      return reExports.test(content);
  }
}

const callRe = /(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(/g;

export function extract(spec: LangSpec, content: string): Extraction {
  const lines = content.split(/\r?\n/);
  const symbols: Sym[] = [];
  const imports: Imp[] = [];
  const calls: Call[] = [];
  const kw = new Set([...SHARED_KEYWORDS, ...(spec.keywords ?? [])]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const ln = i + 1;

    // Names defined ON this line — so we don't mistake `function query(` or
    // `def handle(` for a *call* to query/handle (the def syntax has parens too).
    const definedHere = new Set<string>();
    for (const d of spec.defs) {
      const m = d.re.exec(line);
      if (m && m[1]) {
        definedHere.add(m[1]);
        symbols.push({ name: m[1], kind: d.kind, line: ln, exported: isExported(spec.exportRule, m[1], line, content) });
      }
    }
    for (const re of spec.imports) {
      const m = re.exec(line);
      if (m && m[1]) imports.push({ spec: m[1], line: ln });
    }
    callRe.lastIndex = 0;
    let cm: RegExpExecArray | null;
    while ((cm = callRe.exec(line))) {
      const receiver = cm[1];
      const callee = cm[2]!;
      if (kw.has(callee)) continue;
      if (!receiver && definedHere.has(callee)) continue; // a definition, not a call
      calls.push(receiver ? { callee, receiver, line: ln } : { callee, line: ln });
    }
  }

  // De-dup symbols by (name,line); keep first.
  const seen = new Set<string>();
  const uniqSyms = symbols.filter((s) => {
    const k = `${s.name}@${s.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return { symbols: uniqSyms, imports, calls };
}
