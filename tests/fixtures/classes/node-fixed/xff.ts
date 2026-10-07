// One proxy in front: the client is the last hop, the only one the proxy wrote.
export function clientIp(req: { headers: Record<string, string | undefined> }): string {
  const hops = String(req.headers["x-forwarded-for"] ?? "").split(",");
  return hops[hops.length - 1]!.trim();
}
