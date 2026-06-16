import type { Finding } from "../types.js";

// Render a finding's cross-file taint path as a Mermaid flowchart. Used in the
// Markdown report (GitHub renders it) and embedded as source in the HTML.

function esc(s: string): string {
  return s.replace(/"/g, "'").replace(/[\n\r]/g, " ");
}

export function pathMermaid(f: Finding): string | null {
  if (!f.path || f.path.length < 2) return null;
  const L: string[] = ["flowchart LR"];
  f.path.forEach((p, i) => {
    const tag = i === 0 ? "SOURCE" : i === f.path!.length - 1 ? "SINK" : "hop";
    const sym = p.symbol ? `<br/>${esc(p.symbol)}()` : "";
    L.push(`  n${i}["${tag}<br/>${esc(p.file)}:${p.line}${sym}"]`);
  });
  for (let i = 0; i < f.path.length - 1; i++) L.push(`  n${i} --> n${i + 1}`);
  // style source/sink
  L.push(`  classDef src fill:#fde68a,stroke:#b45309;`);
  L.push(`  classDef snk fill:#fecaca,stroke:#b91c1c;`);
  L.push(`  class n0 src;`);
  L.push(`  class n${f.path.length - 1} snk;`);
  return L.join("\n");
}
