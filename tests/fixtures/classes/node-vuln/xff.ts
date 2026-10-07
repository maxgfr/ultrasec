export function clientIp(req: { headers: Record<string, string | undefined> }): string {
  return String(req.headers["x-forwarded-for"] ?? "").split(",")[0]!.trim();
}
