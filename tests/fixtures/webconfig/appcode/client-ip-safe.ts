// One reverse proxy in front: it appends the address it saw, so the client is
// the LAST hop, the only one the proxy wrote.
export function clientIp(headers: Headers): string | null {
  const hops = (headers.get("x-forwarded-for") ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  return hops.length ? hops[hops.length - 1]! : null;
}
