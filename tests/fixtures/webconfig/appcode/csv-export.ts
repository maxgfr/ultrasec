type Row = { name: string; email: string; city: string };

// Builds the CSV by hand: every cell is quoted, none is neutralized.
export function toCsv(rows: Row[]): string {
  const header = ["Name", "Email", "City"].join(";");
  const body = rows.map((r) => [r.name, r.email, r.city].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(";"));
  return [header, ...body].join("\n");
}

export function csvResponse(rows: Row[]): Response {
  return new Response(toCsv(rows), { headers: { "Content-Type": "text/csv; charset=utf-8" } });
}
