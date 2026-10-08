// The HTML form of the report: the SAME Markdown, rendered to one
// self-contained page — embedded CSS, no script, no external asset, light and
// dark from the reader's system setting.
//
// ── Why a converter and not a second renderer ──────────────────────────────
//
// The previous layout had two renderers for one report, and they drifted: a
// banner, a column or a redaction fixed in the Markdown had to be fixed again
// in 800 lines of HTML templating, and a test had to pin each twice. Rendering
// the one Markdown document makes the two formats the same document by
// construction. The converter only has to understand the subset
// `audit-report.ts` writes — headings, paragraphs, lists (incl. checkboxes),
// tables, block quotes, fenced code, rules and inline code/bold/italic/links —
// so it is small, and anything it does not recognise is printed as escaped
// text, never as markup.
//
// Everything is escaped BEFORE inline formatting is applied, and a link is
// emitted only for an http(s) URL or an in-page anchor: the report quotes code
// and scanner output, and none of it may become markup in a page that gets
// shared.

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** GitHub-compatible heading slug — the Markdown's contents links target these. */
export function headingSlug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .trim()
    .replace(/\s/g, "-");
}

/** Strip inline Markdown to the plain text a heading slug is computed from. */
function plain(s: string): string {
  return s
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
}

function safeHref(url: string): string | undefined {
  if (url.startsWith("#")) return url;
  return /^https?:\/\/[^\s"'<>]+$/i.test(url) ? url : undefined;
}

/** Inline formatting over ALREADY-ESCAPED text. Code spans are cut out first so
 *  nothing inside them is formatted. */
function inline(raw: string): string {
  const codes: string[] = [];
  let s = raw.replace(/`([^`]+)`/g, (_m, c: string) => {
    codes.push(`<code>${esc(c)}</code>`);
    return `\uE000${codes.length - 1}\uE000`;
  });
  s = esc(s);
  // The legacy tier table writes ids as <code>…</code>; restore just that tag.
  s = s.replace(/&lt;code&gt;([^&<]*)&lt;\/code&gt;/g, "<code>$1</code>");
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, text: string, url: string) => {
    const href = safeHref(url.replace(/&amp;/g, "&"));
    return href ? `<a href="${esc(href)}">${text}</a>` : `${text} (${url})`;
  });
  s = s.replace(/&lt;(https?:\/\/[^\s&]+)&gt;/g, (_m, url: string) => `<a href="${esc(url)}">${url}</a>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[\s(])_([^_]+)_(?=$|[\s).,;:])/g, "$1<em>$2</em>");
  s = s.replace(/\\\|/g, "|");
  return s.replace(/\uE000(\d+)\uE000/g, (_m, i: string) => codes[Number(i)] ?? "");
}

function splitRow(line: string): string[] {
  const body = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells: string[] = [];
  let cur = "";
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (ch === "\\" && body[i + 1] === "|") {
      cur += "\\|";
      i++;
    } else if (ch === "|") {
      cells.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  cells.push(cur.trim());
  return cells;
}

/** Markdown (the report subset) → HTML body. */
export function markdownToHtml(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let i = 0;
  const isTableSep = (l: string | undefined) => !!l && /^\|(\s*:?-+:?\s*\|)+\s*$/.test(l.trim());
  while (i < lines.length) {
    const line = lines[i]!;
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = /^```(\w*)\s*$/.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i]!)) body.push(lines[i++]!);
      i++;
      const lang = fence[1] ?? "";
      const html = body
        .map((b) => {
          const e = esc(b);
          if (lang !== "diff") return e;
          if (b.startsWith("+")) return `<span class="add">${e}</span>`;
          if (b.startsWith("-")) return `<span class="del">${e}</span>`;
          return e;
        })
        .join("\n");
      out.push(`<pre${lang ? ` class="lang-${esc(lang)}"` : ""}><code>${html}</code></pre>`);
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1]!.length;
      const text = h[2]!;
      out.push(`<h${level} id="${esc(headingSlug(plain(text)))}">${inline(text)}</h${level}>`);
      i++;
      continue;
    }
    if (/^---\s*$/.test(line)) {
      out.push("<hr>");
      i++;
      continue;
    }
    if (line.startsWith(">")) {
      const block: string[] = [];
      while (i < lines.length && lines[i]!.startsWith(">")) block.push(lines[i++]!.replace(/^>\s?/, ""));
      out.push(`<blockquote class="banner">${markdownToHtml(block.join("\n"))}</blockquote>`);
      continue;
    }
    if (line.trim().startsWith("|") && isTableSep(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i]!.trim().startsWith("|")) rows.push(splitRow(lines[i++]!));
      out.push(
        `<div class="tw"><table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${rows
          .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`)
          .join("")}</tbody></table></div>`,
      );
      continue;
    }
    if (/^\s*[-*] /.test(line)) {
      out.push(list(lines, i, (next) => (i = next)));
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i]!.trim() && !/^(#{1,6}\s|```|>|\s*[-*] |\|)/.test(lines[i]!)) para.push(lines[i++]!);
    if (!para.length) para.push(lines[i++]!);
    out.push(`<p>${inline(para.join(" ").trim())}</p>`);
  }
  return out.join("\n");
}

/** A (possibly nested, two-space indented) bullet list starting at `start`. */
function list(lines: string[], start: number, setNext: (i: number) => void): string {
  const indentOf = (l: string) => /^(\s*)/.exec(l)![1]!.length;
  const base = indentOf(lines[start]!);
  const items: string[] = [];
  let i = start;
  while (i < lines.length && /^\s*[-*] /.test(lines[i]!) && indentOf(lines[i]!) === base) {
    let text = lines[i]!.trim().replace(/^[-*] /, "");
    i++;
    let nested = "";
    if (i < lines.length && /^\s*[-*] /.test(lines[i]!) && indentOf(lines[i]!) > base) nested = list(lines, i, (n) => (i = n));
    const box = /^\[( |x)\] /.exec(text);
    if (box) text = text.slice(4);
    items.push(
      `<li${box ? ' class="task"' : ""}>${box ? `<input type="checkbox" disabled${box[1] === "x" ? " checked" : ""}> ` : ""}${inline(text)}${nested}</li>`,
    );
  }
  setNext(i);
  return `<ul>${items.join("")}</ul>`;
}

const CSS = `
:root{color-scheme:light dark;--bg:#f6f7f9;--surface:#fff;--alt:#eef1f5;--ink:#14181f;--soft:#4e5769;--faint:#79808f;--rule:#dce1ea;--accent:#24487a;--warn-bg:#fff4e5;--warn:#8a4b00;--add:#1f6f3f;--del:#9b2233;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#101319;--surface:#171b23;--alt:#1e232d;--ink:#e6eaf2;--soft:#a3acbe;--faint:#757e92;--rule:#2a303c;--accent:#8daedd;--warn-bg:#2b2112;--warn:#f0b35a;--add:#7fd19b;--del:#e8798a}}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 72px}
h1{font-size:2rem;margin:0 0 8px}
h2{font-size:1.35rem;margin:40px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
h3{font-size:1.1rem;margin:28px 0 8px}
h4{font-size:1rem;margin:22px 0 6px;color:var(--soft)}
h5{font-size:1rem;margin:18px 0 4px;padding:10px 14px;background:var(--surface);border:1px solid var(--rule);border-left:4px solid var(--accent);border-radius:5px}
h2,h3,h4,h5{scroll-margin-top:16px}
p{margin:8px 0}
a{color:var(--accent)}
code{font-family:var(--mono);font-size:.86em;background:var(--alt);border:1px solid var(--rule);border-radius:3px;padding:.05em .3em;word-break:break-word}
pre{background:var(--surface);border:1px solid var(--rule);border-radius:5px;padding:12px;overflow-x:auto}
pre code{background:none;border:0;padding:0}
.add{color:var(--add)}.del{color:var(--del)}
.tw{overflow-x:auto;margin:10px 0}
table{border-collapse:collapse;width:100%;background:var(--surface);font-size:.9em}
th,td{border:1px solid var(--rule);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--alt)}
ul{padding-left:22px}
li{margin:3px 0}
li.task{list-style:none;margin-left:-20px}
blockquote.banner{margin:16px 0;padding:4px 16px;background:var(--warn-bg);border-left:4px solid var(--warn);border-radius:4px}
blockquote.banner h2{border:0;margin:10px 0 4px;color:var(--warn)}
hr{border:0;border-top:1px solid var(--rule);margin:32px 0}
@media print{body{background:#fff}main{max-width:none}}
`;

/** A whole self-contained page around the rendered Markdown. */
export function renderReportHtml(md: string, title = "Security audit report"): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
${markdownToHtml(md)}
</main>
</body>
</html>
`;
}
