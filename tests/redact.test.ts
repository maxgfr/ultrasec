import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isCredentialFinding, redactCredentialLine, redactSecrets } from "../src/redact.js";
import { placeholderArtefacts, redactReviewerText } from "../src/council/redact.js";
import { withStageNote, stageNotes } from "../src/util.js";
import { applyVerdicts } from "../src/verify.js";
import { applyRevalidations, buildRevalidateWorklist } from "../src/revalidate.js";
import { ingestDiscoveries } from "../src/investigate.js";
import type { Dossier } from "../src/store.js";
import type { Finding } from "../src/types.js";

// Auditor prose is folded into findings.json and rendered verbatim into
// REPORT.md/index.html. On a real run a revalidation note quoted the cited line
// from REVALIDATE.todo.json — a seed row — and a full argon2 hash reached the
// report after the detector itself had been fixed to mask it.

// Assembled at runtime so the literal is never a single greppable hash.
const SALT = "c2FsdHNhbHRzYWx0";
const DIGEST = "ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0";
const ARGON = ["$argon2id", "v=19", "m=65536,t=3,p=4", SALT, DIGEST].join("$");

function finding(id: string, over: Partial<Finding> = {}): Finding {
  return {
    id,
    category: "secret",
    cwe: "CWE-798",
    title: "Committed password hash",
    severity: "medium",
    confidence: "low",
    message: "A seed creates an account.",
    tool: "ultrasec",
    status: "open",
    sink: { file: "seed.sql", line: 1 },
    ...over,
  };
}

function dossier(findings: Finding[]): Dossier {
  return {
    manifest: {
      version: "0.0.0",
      schemaVersion: 4,
      repo: "/repo",
      generatedNote: "",
      languages: [],
      toolsRun: [],
      counts: { findings: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
    },
    findings,
    graph: { files: [], edges: [], symbolDefs: {} },
  };
}

describe("redactSecrets — each credential shape", () => {
  it("masks a modular-crypt password hash, keeping the algorithm and cost", () => {
    const out = redactSecrets(`the seed row inserts '${ARGON}' for super`);
    expect(out).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(out).not.toContain(SALT);
    expect(out).not.toContain(DIGEST);
  });

  it("keeps a hash's cost list readable when it sits behind a credential name", () => {
    const out = redactSecrets(`password: "${ARGON}"`);
    expect(out).toBe('password: "$argon2id$v=19$m=65536,t=3,p=4$…"');
  });

  it("masks NAME=value and NAME: value, keeping four characters at most", () => {
    expect(redactSecrets("DB_PASSWORD=Sup3rS3cretValue!")).toBe("DB_PASSWORD=Sup3…");
    expect(redactSecrets("export GITHUB_TOKEN='ghp_abcdefghijklmnopqrstuvwxyz0123'")).toBe("export GITHUB_TOKEN='ghp_…'");
    expect(redactSecrets("  api_key: sk-live-0123456789abcdef")).toBe("  api_key: sk-l…");
    expect(redactSecrets('{ "client_secret": "s3cr3t-value-123456" }')).toBe('{ "client_secret": "s3cr…" }');
    expect(redactSecrets("PRIVATE_KEY=abcdefghijklmnop")).toBe("PRIVATE_KEY=abcd…");
    expect(redactSecrets("APIKEY=abcdefghijklmnop")).toBe("APIKEY=abcd…");
    expect(redactSecrets("passwd=hunter22")).toBe("passwd=hu…");
  });

  it("keeps a short value from being kept whole", () => {
    // Four characters of a six-character password is most of it.
    expect(redactSecrets("password=abc123")).toBe("password=ab…");
    expect(redactSecrets("password=abcd")).toBe("password=a…");
  });

  it("masks the password in URI userinfo, keeping user and host", () => {
    expect(redactSecrets("DATABASE_URL is postgres://app:Pa55w0rd@db.internal:5432/app")).toBe("DATABASE_URL is postgres://app:…@db.internal:5432/app");
    expect(redactSecrets("redis://:s3cret@cache:6379")).toBe("redis://:…@cache:6379");
  });

  it("masks a PEM private key body, terminated or cut short", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1y\nabcdef==\n-----END RSA PRIVATE KEY-----";
    expect(redactSecrets(`key file:\n${pem}\ndone`)).toBe("key file:\n-----BEGIN RSA PRIVATE KEY-----…-----END RSA PRIVATE KEY-----\ndone");
    expect(redactSecrets("quoted: -----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASC")).toBe("quoted: -----BEGIN PRIVATE KEY-----…");
  });

  it("masks provider token shapes and an Authorization header that carry no name", () => {
    const aws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    expect(redactSecrets(`the key ${aws} is in the deploy script`)).toBe("the key AKIA… is in the deploy script");
    expect(redactSecrets("curl -H 'Authorization: Bearer abcdef0123456789abcdef'")).toBe("curl -H 'Authorization: Bearer abcd…'");
    const slack = ["xoxb", "123456789012", "abcdefghijkl"].join("-");
    expect(redactSecrets(`posts with ${slack}`)).not.toContain("abcdefghijkl");
  });

  it("leaves the argument a refutation makes intact", () => {
    // Where the value comes FROM is the whole point of "the key is read from the
    // environment"; masking it would destroy the note it protects.
    for (const text of [
      "const token = req.headers.authorization;",
      "API_KEY = os.getenv('API_KEY')",
      "password: process.env.DB_PASSWORD",
      "SECRET_KEY=${SECRET_KEY}",
      "if (token === undefined) return",
      "the token: is never logged",
      "tokens: 3",
      "password: null",
      "no credential here at all",
    ]) {
      expect(redactSecrets(text)).toBe(text);
    }
  });

  it("still masks a JWT even though it is dotted like a member access", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
    expect(redactSecrets(`token=${jwt}`)).toBe("token=eyJh…");
  });

  it("is idempotent", () => {
    const aws = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const text = `DB_PASSWORD=Sup3rS3cretValue! ${ARGON} postgres://u:p4ss@h -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY----- ${aws} Authorization: Bearer abcdef0123456789abcdef`;
    const once = redactSecrets(text);
    expect(redactSecrets(once)).toBe(once);
  });
});

describe("credential findings and their cited line", () => {
  it("recognises a credential finding by category, CWE or title", () => {
    expect(isCredentialFinding({ category: "secret", title: "x" })).toBe(true);
    expect(isCredentialFinding({ category: "crypto", cwe: "CWE-916", title: "weak hash" })).toBe(true);
    expect(isCredentialFinding({ category: "other", title: "Insufficiently protected credentials (CWE-522)" })).toBe(true);
    expect(isCredentialFinding({ category: "taint", cwe: "CWE-89", title: "SQL injection" })).toBe(false);
  });

  it("masks a bare token with no name in front of it", () => {
    const out = redactCredentialLine(`  headers: { Authorization: "Bearer ghp_abcdefghij0123456789KLMNOP" },`);
    expect(out).not.toContain("abcdefghij0123456789KLMNOP");
    expect(out).toContain("Authorization");
    // A long identifier with no digit is code, not a token.
    expect(redactCredentialLine("const VERY_LONG_CONSTANT_NAME_HERE = load();")).toBe("const VERY_LONG_CONSTANT_NAME_HERE = load();");
  });
});

describe("authored notes are redacted on the way into the dossier", () => {
  it("withStageNote masks the note and stays idempotent", () => {
    const once = withStageNote("engine prose", "Revalidation", "still-valid", `line is still '${ARGON}'`);
    expect(once).not.toContain(DIGEST);
    expect(stageNotes(once)).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(withStageNote(once, "Revalidation", "still-valid", `line is still '${ARGON}'`)).toBe(once);
  });

  it("verify --apply folds a redacted note and exploit path", () => {
    const r = applyVerdicts(dossier([finding("a")]), [
      { id: "a", verdict: "supported", note: `seed.sql:1 inserts ${ARGON}`, exploitPath: "login as super with SUPER_PASSWORD=Adm1nAdm1n!Adm1n" },
    ]);
    const a = r.findings[0]!;
    expect(a.message).not.toContain(DIGEST);
    expect(a.message).toContain("Verdict (supported): seed.sql:1 inserts $argon2id$v=19$m=65536,t=3,p=4$…");
    expect(a.exploitPath).toBe("login as super with SUPER_PASSWORD=Adm1…");
  });

  it("revalidate --apply folds a redacted note — the path that leaked", () => {
    const r = applyRevalidations(dossier([finding("a", { status: "confirmed" })]), [
      { id: "a", verdict: "still-valid", note: `current line: ('admin@example.org', '${ARGON}', 'super')` },
    ]);
    expect(r.findings[0]!.message).not.toContain(SALT);
    expect(r.findings[0]!.message).toContain("Revalidation (still-valid): current line:");
  });

  it("investigate --apply redacts the hunter's write-up", () => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-redact-inv-"));
    writeFileSync(join(repo, "config.js"), "module.exports = {\n  stripeKey: 'sk_live_0123456789abcdefABCDEF',\n};\n");
    const r = ingestDiscoveries(
      dossier([]),
      [
        {
          title: "Hard-coded Stripe key",
          category: "secret",
          severity: "high",
          message: "config.js ships STRIPE_SECRET_KEY=sk_live_0123456789abcdefABCDEF to every client",
          file: "config.js",
          line: 2,
          path: [{ file: "config.js", line: 2, why: "api_key: sk_live_0123456789abcdefABCDEF" }],
        },
      ],
      repo,
    );
    const f = r.findings[0]!;
    expect(f.message).toContain("STRIPE_SECRET_KEY=sk_l…");
    expect(JSON.stringify(f)).not.toContain("0123456789abcdefABCDEF");
  });
});

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!gitAvailable())("REVALIDATE.todo.json never quotes a credential", () => {
  function repoWithSeed(): string {
    const dir = mkdtempSync(join(tmpdir(), "ultrasec-redact-reval-"));
    const git = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { stdio: "ignore" });
    git("init", "-q");
    git("config", "user.email", "t@example.com");
    git("config", "user.name", "t");
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "seed.sql"), `INSERT INTO users VALUES ('admin@example.org', '${ARGON}', 'super');\n`);
    writeFileSync(join(dir, "src", "db.js"), "const token = req.query.token; db.query(token);\n");
    git("add", "-A");
    git("commit", "-qm", "init");
    return dir;
  }

  it("masks the cited line of a credential finding, and only of one", () => {
    const repo = repoWithSeed();
    const items = buildRevalidateWorklist(
      dossier([
        finding("cred", { status: "confirmed" }),
        finding("sqli", { status: "confirmed", category: "taint", cwe: "CWE-89", title: "SQL injection", sink: { file: "src/db.js", line: 1 } }),
      ]),
      repo,
    );
    const cred = items.find((i) => i.id === "cred")!;
    expect(cred.currentLine).toContain("$argon2id$v=19$m=65536,t=3,p=4$…");
    expect(cred.currentLine).not.toContain(DIGEST);
    // A code finding's line is the evidence the revalidator reads; it stays whole.
    expect(items.find((i) => i.id === "sqli")!.currentLine).toBe("const token = req.query.token; db.query(token);");
  });
});

// ── One definition of a secret ───────────────────────────────────────────────
// Stage notes (engine) and reviewer output (council) used to be redacted by two
// modules that shared a function name and nothing else. Every literal below is
// assembled at runtime so the test file itself is never a greppable secret.

const HEX40 = ["a1b2c3d4e5", "f6a7b8c9d0", "e1f2a3b4c5", "d6e7f8a9b0"].join("");
const JWT = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTYifQ", "c2lnbmF0dXJlX3Zh"].join(".");
const AWS = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
const PLACEHOLDER = ["SECRETGATE", "ab1426b6f023"].join("_");
const UUID = "123e4567-e89b-12d3-a456-426614174000";

const SHARED_TABLE: [label: string, input: string, expected: string][] = [
  ["argon2 hash", `seed row '${ARGON}'`, "seed row '$argon2id$v=19$m=65536,t=3,p=4$…'"],
  ["NAME=value", "DB_PASSWORD=Sup3rS3cretValue!", "DB_PASSWORD=Sup3…"],
  ["JSON password", `{"password": "${["hunter2", "hunter2"].join("")}"}`, '{"password": "hunt…"}'],
  ["JSON passphrase with spaces", `{"password": "correct horse ${"battery"} staple"}`, '{"password": "corr…"}'],
  ["URI userinfo", `postgres://app:${["pa55", "word"].join("")}@db:5432/app`, "postgres://app:…@db:5432/app"],
  ["JWT", `token ${JWT}`, "token eyJh…"],
  ["40-char hex key, named", `SIGNING_KEY=${HEX40}`, "SIGNING_KEY=a1b2…"],
  ["40-char hex key, quoted", `"api_key": "${HEX40}"`, '"api_key": "a1b2…"'],
  ["AWS access key", `the key ${AWS} ships`, "the key AKIA… ships"],
  ["SECRETGATE placeholder, named", `TOKEN=${PLACEHOLDER}`, `TOKEN=${PLACEHOLDER}`],
  ["SECRETGATE placeholder, bare", `replaced by ${PLACEHOLDER}`, `replaced by ${PLACEHOLDER}`],
  ["UUID", `request ${UUID} failed`, `request ${UUID} failed`],
  ["process.env reference", "password: process.env.DB_PASSWORD", "password: process.env.DB_PASSWORD"],
  ["already masked", "DB_PASSWORD=Sup3… and postgres://app:…@db", "DB_PASSWORD=Sup3… and postgres://app:…@db"],
  ["the council's former marker", "JWT_SECRET=‹redacted›", "JWT_SECRET=‹redacted›"],
];

describe("stage notes and council output agree on what a secret is", () => {
  it.each(SHARED_TABLE)("%s", (_label, input, expected) => {
    const note = redactSecrets(input);
    const reviewer = redactReviewerText(input);
    expect(note).toBe(expected);
    expect(reviewer).toBe(expected);
    // Idempotent on either path, and across them.
    expect(redactSecrets(note)).toBe(note);
    expect(redactReviewerText(reviewer)).toBe(reviewer);
    expect(redactReviewerText(note)).toBe(note);
    // The mask is never read back as a masking placeholder by the claim parser:
    // only a placeholder that was already in the input is reported.
    expect(placeholderArtefacts(reviewer)).toEqual(placeholderArtefacts(input));
  });

  it("a deep-redacted note keeps none of the table's secrets", () => {
    const all = SHARED_TABLE.map(([, input]) => input).join("\n");
    for (const out of [redactSecrets(all), redactReviewerText(all)]) {
      for (const secret of [SALT, DIGEST, "S3cretValue", HEX40.slice(4), JWT.slice(4), AWS.slice(4)]) expect(out).not.toContain(secret);
    }
  });
});

describe("bare runs: where the long-token rule applies, and where it would destroy evidence", () => {
  const B64_KEY = ["c2VjcmV0a2V5", "MTIzNDU2Nzg5", "MGFiY2RlZg9x"].join("");

  it("notes keep a bare hex run — revalidate writes the fixing commit's full sha", () => {
    expect(redactSecrets(`fixed in ${HEX40}`)).toBe(`fixed in ${HEX40}`);
    const r = applyRevalidations(dossier([finding("a", { status: "confirmed" })]), [{ id: "a", verdict: "fixed", fixedIn: HEX40 }]);
    expect(r.findings[0]!.message).toContain(`fixed in ${HEX40}`);
    expect(r.findings[0]!.fixedIn).toBe(HEX40);
  });

  it("reviewer output masks bare key material, not identifiers, paths, UUIDs or placeholders", () => {
    expect(redactReviewerText(`key ${HEX40}`)).toBe("key a1b2…");
    expect(redactReviewerText(`blob ${B64_KEY}`)).toBe("blob c2Vj…");
    for (const text of ["handleUserAuthenticationCallbackForProviderV2", "src/components/Button/index.tsx", `see ${UUID}`, `was ${PLACEHOLDER}`]) {
      expect(redactReviewerText(text)).toBe(text);
    }
    // Notes keep the same bare run: no name, no shape, and it could be a digest.
    expect(redactSecrets(`blob ${B64_KEY}`)).toBe(`blob ${B64_KEY}`);
  });

  it("a credential line masks any opaque run, UUIDs included, but never a placeholder", () => {
    expect(redactCredentialLine(`const k = "${HEX40}";`)).toBe('const k = "a1b2…";');
    expect(redactCredentialLine(`heroku: ${UUID}`)).toBe("heroku: 123e…");
    expect(redactCredentialLine(`token ${PLACEHOLDER}`)).toBe(`token ${PLACEHOLDER}`);
    const once = redactCredentialLine(`a ${HEX40} b ${B64_KEY}`);
    expect(redactCredentialLine(once)).toBe(once);
  });
});
