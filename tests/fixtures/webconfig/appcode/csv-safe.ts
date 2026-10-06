type Row = { name: string; email: string; city: string };

// A cell starting with = + - @ (or a tab / CR) is a formula to a spreadsheet.
const FORMULA_START = /^[=+\-@\t\r]/;
const cell = (v: unknown) => {
  const s = String(v);
  return `"${(FORMULA_START.test(s) ? `'${s}` : s).replace(/"/g, '""')}"`;
};

export function toCsv(rows: Row[]): string {
  const header = ["Name", "Email", "City"].join(";");
  const body = rows.map((r) => [r.name, r.email, r.city].map(cell).join(";"));
  return [header, ...body].join("\n");
}
