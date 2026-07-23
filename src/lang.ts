// Language registry for ultrasec's cross-file taint reasoning. Symbol/import/call
// extraction now comes from the vendored codeindex engine (see src/scan.ts) — this
// module only keeps the file→language mapping and the extraction record shapes the
// rest of ultrasec consumes. Breadth (~15 languages) is what matters here: the
// engine emits richer metadata, but the catalogs gate on these stable ultrasec ids
// (e.g. "javascript"/"c_cpp", not the engine's "typescript"/"cpp").

export interface LangSpec {
  id: string;
  extensions: string[];
}

/** A defined symbol. `kind` is a free-form string (the engine emits a richer set
 *  than ultrasec's former closed enum); no consumer switches on it narrowly.
 *  `endLine` is the symbol's last line when the extractor knows it (used by the
 *  raw caller-index consumer). */
export interface Sym {
  name: string;
  kind: string;
  line: number;
  endLine?: number;
  exported: boolean;
}
/** An import/require. Only the specifier is load-bearing (the resolver needs it);
 *  the engine's raw refs carry no line, so ultrasec no longer tracks one. */
export interface Imp {
  spec: string;
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

export const LANGS: LangSpec[] = [
  { id: "javascript", extensions: ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"] },
  { id: "python", extensions: ["py", "pyi"] },
  { id: "go", extensions: ["go"] },
  { id: "java", extensions: ["java"] },
  { id: "ruby", extensions: ["rb"] },
  { id: "php", extensions: ["php"] },
  { id: "rust", extensions: ["rs"] },
  { id: "c_cpp", extensions: ["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx"] },
  { id: "csharp", extensions: ["cs"] },
  { id: "kotlin", extensions: ["kt", "kts"] },
  { id: "swift", extensions: ["swift"] },
  { id: "scala", extensions: ["scala", "sc"] },
  { id: "shell", extensions: ["sh", "bash", "zsh"] },
  { id: "lua", extensions: ["lua"] },
  { id: "elixir", extensions: ["ex", "exs"] },
];

const byExt = new Map<string, LangSpec>();
for (const l of LANGS) for (const ext of l.extensions) byExt.set(ext, l);

export function langForFile(rel: string): LangSpec | undefined {
  const dot = rel.lastIndexOf(".");
  if (dot < 0) return undefined;
  return byExt.get(rel.slice(dot + 1).toLowerCase());
}
