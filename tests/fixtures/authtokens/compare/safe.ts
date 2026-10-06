import { timingSafeEqual } from "node:crypto";

export function tokenMatches(provided: string): boolean {
  const expected = process.env.SYNC_JOB_TOKEN;
  if (expected === undefined || expected === "") return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
