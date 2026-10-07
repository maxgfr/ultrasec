type Row = { name: string; email: string };

const FORMULA_START = /^[=+\-@\t\r]/;
const cell = (v: string) => (FORMULA_START.test(v) ? `'${v}` : v);

export function exportCsv(rows: Row[]): Response {
  const body = rows.map((r) => [r.name, r.email].map(cell).join(",")).join("\n");
  return new Response(body, { headers: { "Content-Type": "text/csv" } });
}
