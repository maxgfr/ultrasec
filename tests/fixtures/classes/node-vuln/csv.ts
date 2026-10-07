type Row = { name: string; email: string };

export function exportCsv(rows: Row[]): Response {
  const body = rows.map((r) => [r.name, r.email].join(",")).join("\n");
  return new Response(body, { headers: { "Content-Type": "text/csv" } });
}
