import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { auditSecrets, downgradeEncryptedAtRest, encryptedShapeOf, isLiteralSecret } from "../src/secrets.js";
import type { Finding } from "../src/types.js";

// Issue #10 (defect 3). Measured on a public k8s repo: 41 secret findings on
// files that are ciphertext BY DESIGN, and zero on the plaintext production
// Postgres password sitting next to them. The noisiest class was the one class
// that cannot be a leak; the one credential that WAS a leak looked like a URL.

const FIXTURE = join(import.meta.dirname, "fixtures", "secrets-uri");

const secret = (file: string, over: Partial<Finding> = {}): Finding => ({
  id: `id-${file}`,
  category: "secret",
  cwe: "CWE-798",
  title: "Generic API Key",
  severity: "high",
  confidence: "medium",
  message: `Hardcoded secret at ${file}:1`,
  tool: "gitleaks",
  sink: { file, line: 1 },
  status: "open",
  ...over,
});

describe("auditSecrets — credential URIs survive partial templating", () => {
  const findings = auditSecrets(FIXTURE);
  const at = (file: string) => findings.filter((f) => f.sink?.file === file);

  it("flags a literal password whose neighbouring components are templated", () => {
    // `postgresql://$(username):<literal>@$(host):$(port)/db` — the shape that
    // reads as configuration rather than as a credential, which is how it
    // survives review and why entropy heuristics skip it.
    const hits = at(".kontinuous/env/prod/values.yaml");
    expect(hits.length).toBe(1);
    expect(hits[0]!.severity).toBe("high");
    expect(hits[0]!.cwe).toBe("CWE-798");
    expect(hits[0]!.category).toBe("secret");
  });

  it("flags an untemplated credential under any scheme", () => {
    expect(at("config/broker.toml").length).toBe(1);
  });

  it("stays quiet when the password itself is templated", () => {
    expect(at(".kontinuous/env/dev/values.yaml")).toEqual([]);
  });

  it("stays quiet on documentation placeholders", () => {
    expect(at("docs/setup.md")).toEqual([]);
  });

  it("does not redact-fail: the reported message never contains the password", () => {
    const hit = at(".kontinuous/env/prod/values.yaml")[0]!;
    expect(hit.message).not.toMatch(/Kx7pQ2mLw9v/);
  });

  it("cites a resolvable file:line", () => {
    for (const f of findings) {
      expect(f.sink?.file).toBeTruthy();
      expect(f.sink!.line).toBeGreaterThan(0);
    }
  });

  it("does not scan inside encrypted-at-rest files at all", () => {
    expect(findings.some((f) => f.sink?.file.startsWith("sealed/"))).toBe(false);
  });
});

describe("isLiteralSecret", () => {
  it("accepts a real-looking literal", () => {
    expect(isLiteralSecret("Kx7pQ2mLw9v")).toBe(true);
  });

  it("rejects every templating dialect", () => {
    for (const t of ["$(password)", "${PG_PASS}", "$PGPASS", "{{ .Values.pw }}", "<your-password>", "%(pw)s", "#{pw}"]) {
      expect(isLiteralSecret(t), t).toBe(false);
    }
  });

  it("rejects placeholders and stubs", () => {
    for (const t of ["password", "changeme", "xxxx", "****", "REDACTED", "your_password", "hunter2"]) {
      expect(isLiteralSecret(t), t).toBe(false);
    }
  });
});

describe("encrypted-at-rest findings are de-prioritized, never dropped", () => {
  it("recognises SealedSecret by filename and by kind", () => {
    expect(encryptedShapeOf("sealed/db.sealed-secret.yaml", "")!.id).toBe("sealed-secret");
    expect(encryptedShapeOf("anything.yaml", "apiVersion: v1\nkind: SealedSecret\n")!.id).toBe("sealed-secret");
  });

  it("covers schemes beyond SealedSecrets", () => {
    expect(encryptedShapeOf("x.yaml", "$ANSIBLE_VAULT;1.1;AES256\n")!.id).toBe("ansible-vault");
    expect(encryptedShapeOf("x.txt", "-----BEGIN AGE ENCRYPTED FILE-----\n")!.id).toBe("age");
    expect(encryptedShapeOf("x.yaml", "a: b\nsops:\n  kms: []\n")!.id).toBe("sops");
  });

  it("leaves an ordinary file alone", () => {
    expect(encryptedShapeOf("values.yaml", "password: hunter2\n")).toBeUndefined();
  });

  it("downgrades to info and counts, rather than filtering", () => {
    const input = [secret("sealed/db.sealed-secret.yaml"), secret("sealed/app.enc.yaml"), secret(".kontinuous/env/prod/values.yaml")];
    const { findings, downgraded } = downgradeEncryptedAtRest(input, FIXTURE);
    expect(downgraded).toBe(2);
    // Nothing disappears — the report is re-ordered, not shortened.
    expect(findings.length).toBe(3);
    const sealed = findings.filter((f) => f.sink!.file.startsWith("sealed/"));
    expect(sealed.every((f) => f.severity === "info")).toBe(true);
    expect(sealed.every((f) => f.confidence === "low")).toBe(true);
    expect(sealed.every((f) => /ciphertext is the point of the file/.test(f.message))).toBe(true);
    // The real one is untouched.
    expect(findings.find((f) => f.sink!.file.endsWith("prod/values.yaml"))!.severity).toBe("high");
  });

  it("never downgrades a credential a scanner VERIFIED as live", () => {
    // A live credential is live, whatever the file format claims to be.
    const input = [secret("sealed/db.sealed-secret.yaml", { verified: true })];
    const { findings, downgraded } = downgradeEncryptedAtRest(input, FIXTURE);
    expect(downgraded).toBe(0);
    expect(findings[0]!.severity).toBe("high");
  });

  it("leaves non-secret findings alone wherever they sit", () => {
    const input = [secret("sealed/db.sealed-secret.yaml", { category: "config", severity: "medium" })];
    const { findings, downgraded } = downgradeEncryptedAtRest(input, FIXTURE);
    expect(downgraded).toBe(0);
    expect(findings[0]!.severity).toBe("medium");
  });
});
