// Format detection + line parsing for `ultrasec logs`. Pure functions, no I/O —
// the streaming engine (`analyze.ts`) owns reading files; this module only turns
// text into structured events. Kept extensible: syslog lands in a follow-up task
// by adding a union member + a vote/parse branch, nothing here restructures.

export const LOG_FORMATS = ["nginx-combined", "common", "json-lines", "generic", "raw"] as const;
export type LogFormat = (typeof LOG_FORMATS)[number];

/** One parsed log line. Everything but `message`/`raw` is best-effort — a line
 *  that doesn't match its format's shape degrades to `{message: line, raw: line}`. */
export interface ParsedEvent {
  ts?: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  ua?: string;
  message: string;
  raw: string;
}

// Combined/common access-log line: `IP - user [date] "METHOD path proto" status bytes`
// (+ optional `"referrer" "ua"` for combined). Capture groups (1-indexed):
// 1 ip, 2 user, 3 date, 4 method, 5 path, 6 status, 7 bytes, 8 referrer, 9 ua.
const ACCESS_RE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^" ]+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;
const ISO_TS_RE = /^\d{4}-\d{2}-\d{2}[T ]/;
const BRACKET_TS_RE = /^\[\d{4}-\d{2}-\d{2}/;
const GENERIC_ISO_RE = /^(\d{4}-\d{2}-\d{2}[T ][0-9:.,Z+-]*)/;
const GENERIC_BRACKET_RE = /^\[(\d{4}-\d{2}-\d{2}[^\]]*)\]/;

const MAX_VOTE_SAMPLE = 50;

/** Vote over the first ~50 non-blank sample lines to pick a format. A format
 *  needs a strict majority of the sample to win; ties/no-majority fall back to
 *  "raw" (never guess a structured format off a minority of lines). */
export function detectFormat(sampleLines: string[]): LogFormat {
  const lines = sampleLines.filter((l) => l.trim().length > 0).slice(0, MAX_VOTE_SAMPLE);
  if (!lines.length) return "raw";

  let combined = 0;
  let common = 0;
  let json = 0;
  let generic = 0;

  for (const line of lines) {
    const m = ACCESS_RE.exec(line);
    if (m) {
      if (m[8] !== undefined) combined++;
      else common++;
      continue;
    }
    const trimmed = line.trimStart();
    if (trimmed.startsWith("{")) {
      try {
        const parsed: unknown = JSON.parse(trimmed);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          json++;
          continue;
        }
      } catch {
        /* not JSON — fall through to timestamp checks */
      }
    }
    if (ISO_TS_RE.test(line) || BRACKET_TS_RE.test(line)) {
      generic++;
    }
  }

  const total = lines.length;
  const tally: [LogFormat, number][] = [
    ["nginx-combined", combined],
    ["common", common],
    ["json-lines", json],
    ["generic", generic],
  ];
  tally.sort((a, b) => b[1] - a[1]);
  const [topFormat, topVotes] = tally[0]!;
  return topVotes > 0 && topVotes >= total / 2 ? topFormat : "raw";
}

function pick(obj: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  return undefined;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function asStatus(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function parseAccessLine(line: string): ParsedEvent {
  const m = ACCESS_RE.exec(line);
  if (!m) return { message: line, raw: line };
  // Group 8 (referrer) is intentionally skipped — not part of ParsedEvent's
  // documented shape; it's still matchable via `raw` for signature detection.
  const [, ip, , ts, method, path, statusRaw, , , ua] = m;
  return {
    ts,
    ip,
    method,
    path,
    status: asStatus(statusRaw),
    ua,
    message: line,
    raw: line,
  };
}

function parseJsonLine(line: string): ParsedEvent {
  const trimmed = line.trimStart();
  if (!trimmed.startsWith("{")) return { message: line, raw: line };
  let obj: unknown;
  try {
    obj = JSON.parse(trimmed);
  } catch {
    return { message: line, raw: line };
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { message: line, raw: line };
  const rec = obj as Record<string, unknown>;
  const message = asString(pick(rec, ["msg", "message"]));
  return {
    ts: asString(pick(rec, ["time", "@timestamp", "timestamp"])),
    ip: asString(pick(rec, ["ip", "remote_addr", "client_ip"])),
    path: asString(pick(rec, ["path", "url", "request"])),
    status: asStatus(pick(rec, ["status", "status_code"])),
    ua: asString(pick(rec, ["user_agent", "ua"])),
    message: message ?? line,
    raw: line,
  };
}

function parseGenericLine(line: string): ParsedEvent {
  const iso = GENERIC_ISO_RE.exec(line);
  const bracket = GENERIC_BRACKET_RE.exec(line);
  const ts = iso?.[1] ?? bracket?.[1];
  return { ts, message: line, raw: line };
}

/** Parse one line under a known format. Never throws — a line that doesn't
 *  match its format's shape degrades to `{message: line, raw: line}`. */
export function parseLine(fmt: LogFormat, line: string): ParsedEvent {
  switch (fmt) {
    case "nginx-combined":
    case "common":
      return parseAccessLine(line);
    case "json-lines":
      return parseJsonLine(line);
    case "generic":
      return parseGenericLine(line);
    default:
      return { message: line, raw: line };
  }
}
