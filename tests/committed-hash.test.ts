import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditAuthTokens } from "../src/authtokens.js";

// A password hash committed to the repository.
//
// The most serious finding of a real audit was an `INSERT INTO auth.users`
// carrying a literal argon2id hash for a `super` account, in a SQL file
// re-executed on every preprod deployment. Nothing in the engine looked at it:
// `.sql` was in NO extension set — not a language, not the secret scanner's,
// not the IaC auditor's — and the generated report listed "passwords are hashed
// with argon2" among the repo's strengths. A second, never-reported pair sat in
// the initial database migration.
//
// A seed file does not merely CONTAIN an account, it CREATES one, in every
// environment that runs it. That is why this is `secret`/CWE-798 and not a
// cryptography note.

function repoWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "ultrasec-pwhash-"));
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, body);
  }
  return dir;
}

const hashes = (repo: string) => auditAuthTokens(repo).filter((f) => f.cwe === "CWE-798" && /hash/i.test(f.title));

describe("committed password hash", () => {
  it("finds an argon2 hash seeded by a SQL migration — the shape that was invisible", () => {
    const repo = repoWith({
      "sql/post-restore.sql": `INSERT INTO auth.users (email, password, name, role)
VALUES (
  'admin@example.gouv.fr',
  '$argon2id$v=19$m=65536,t=3,p=4$dTv43xyuOUbJbECoftnQ$aC5yrzCJalCLMLwzuJYi9kQ2OPCWoGRagfGR9BMpj8',
  'Administrateur',
  'super'
);
`,
    });
    const found = hashes(repo);
    expect(found).toHaveLength(1);
    expect(found[0]!.sink!.file).toBe("sql/post-restore.sql");
    expect(found[0]!.sink!.line).toBe(4);
    expect(found[0]!.severity).toBe("high");
    expect(found[0]!.category).toBe("secret");
    // The message has to say the file CREATES the account, not just holds a hash.
    expect(found[0]!.message).toContain("CREATES");
    expect(found[0]!.message).toContain("git history");
  });

  it("covers the other formats and the data files they hide in", () => {
    const repo = repoWith({
      "seed.yaml": `password: "$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUV1234567890"\n`,
      "fixtures.json": `{ "pw": "$scrypt$ln=16,r=8,p=1$aaaaaaaaaaaaaaaa$bbbbbbbbbbbbbbbb" }\n`,
      "users.sql": `INSERT INTO u VALUES ('$pbkdf2-sha256$29000$salt$derivedkeyhere');\n`,
    });
    expect(
      hashes(repo)
        .map((f) => f.sink!.file)
        .sort(),
    ).toEqual(["fixtures.json", "seed.yaml", "users.sql"]);
  });

  it("does not fire on a shell positional or an ordinary dollar string", () => {
    // `$6$`/`$5$` (sha512crypt) are the same shape but collide with shell
    // expansion, so the rule deliberately excludes them.
    const repo = repoWith({
      "run.sh": `echo "$1 $2 $6"\nPRICE='$5$'\ncost=$(( $3 + $4 ))\n`,
      "app.js": `const tpl = \`\${a}$\{b}\`;\nconst re = /\\$\\{/;\n`,
    });
    expect(hashes(repo)).toHaveLength(0);
  });

  it("still reports the code-only shapes it always did", () => {
    const repo = repoWith({ "auth.js": `const jwt = require("jsonwebtoken");\njwt.verify(t, k, { algorithms: ["none"] });\n` });
    expect(auditAuthTokens(repo).some((f) => /none/i.test(f.title))).toBe(true);
  });
});
