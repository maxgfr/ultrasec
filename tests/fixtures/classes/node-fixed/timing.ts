import { createHash, timingSafeEqual } from "node:crypto";

const digest = (v: string) => createHash("sha256").update(v).digest();

export function checkApiKey(req: { headers: Record<string, string | undefined> }): boolean {
  return timingSafeEqual(digest(req.headers["x-api-key"] ?? ""), digest(process.env.PARTNER_API_KEY ?? ""));
}
