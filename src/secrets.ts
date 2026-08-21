import { join } from "node:path";
import { readText, walk } from "./walk.js";
import type { Finding } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";
import { cweUrl } from "./catalog.js";

// Two credential classes a scanner belt handles badly, in opposite directions.
//
// NOISE. On a public k8s repo, the secret scanners produced double-digit hits on
// SealedSecret manifests — files whose entire content is ciphertext BY DESIGN,
// which is the point of committing them. On any real infrastructure repo that is
// the dominant secret-finding class, and not one of them can be a leak. What IS
// worth checking there is whether the decryption key is committed too, which no
// filename rule can tell you.
//
// BLIND SPOT. A credential embedded in a connection string is easy to miss when
// the components AROUND it are templated: `scheme://$(user):hunter2@$(host)/db`
// reads as configuration rather than as a credential, so entropy and format
// heuristics skip the line. (The report that prompted this file cited such a
// leak; re-checking the pinned commit, that particular password was `$(password)`
// — templated, and correctly ignored by every scanner including this one. The
// class is real regardless: the same pass finds a literal 16-character password
// in that repo's `docker-compose.yml` that no scanner reported.)
//
// Same discipline as the rest of the engine: nothing is silently dropped. A
// finding inside an encrypted-at-rest file is DOWNGRADED with the scheme named,
// and the count is reported in the manifest, so a suppressed class stays visible.

// Local, like the other always-on auditors (authtokens/webconfig/cloud each keep
// their own): four lines is cheaper than a shared import nobody can move.
function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i === -1 ? "" : rel.slice(i + 1).toLowerCase();
}

// ── Encrypted at rest ────────────────────────────────────────────────────────

export interface EncryptedShape {
  id: string;
  /** Named in the downgraded finding's message, so the reader can check it. */
  label: string;
  /** Filename globs (substring match on the repo-relative path, lowercased). */
  paths?: string[];
  /** A marker that proves the file's secrets are ciphertext. */
  marker?: RegExp;
}

/**
 * Files whose credential-shaped content is ciphertext by construction. Kept as
 * data so adding a scheme is a row: every one of these is a format whose whole
 * purpose is to make a secret safe to commit.
 */
export const ENCRYPTED_AT_REST: EncryptedShape[] = [
  { id: "sealed-secret", label: "Bitnami SealedSecret", paths: [".sealed-secret.yaml", ".sealedsecret.yaml"], marker: /(^|\n)\s*kind:\s*SealedSecret\b/ },
  {
    id: "sops",
    label: "SOPS-encrypted file",
    paths: [".sops.yaml", ".sops.yml", ".enc.yaml", ".enc.yml", ".enc.json", ".enc.env"],
    marker: /(^|\n)\s*sops:\s*(\n|$)|"sops"\s*:\s*\{/,
  },
  { id: "ansible-vault", label: "Ansible Vault", marker: /\$ANSIBLE_VAULT;\d/ },
  { id: "age", label: "age-encrypted file", marker: /-----BEGIN AGE ENCRYPTED FILE-----/ },
  { id: "pgp", label: "PGP/GPG armoured message", marker: /-----BEGIN PGP MESSAGE-----/ },
  // git-crypt writes a NUL-delimited `GITCRYPT` magic in the first bytes. Matched
  // without the NUL itself: a control character in a regex is a lint error here,
  // and anchoring `GITCRYPT` to the head of the file is just as specific.
  { id: "git-crypt", label: "git-crypt blob", marker: /^.{0,4}GITCRYPT/ },
  { id: "jasypt", label: "Jasypt/Jenkins encrypted value", marker: /\bENC\([A-Za-z0-9+/=]{16,}\)|\{AQAA[A-Za-z0-9+/=]{16,}\}/ },
];

/** The shape covering `rel`, if any. `content` is only consulted for `marker`. */
export function encryptedShapeOf(rel: string, content: string): EncryptedShape | undefined {
  const lower = rel.toLowerCase();
  for (const shape of ENCRYPTED_AT_REST) {
    if (shape.paths?.some((p) => lower.endsWith(p))) return shape;
    if (shape.marker?.test(content)) return shape;
  }
  return undefined;
}

/**
 * De-prioritize secret findings whose location is an encrypted-at-rest file.
 *
 * NOT a filter: the finding stays, at `info`/`low` with the scheme named, and
 * the caller reports the count. Dropping them outright would leave the run
 * unable to say how many were discarded, which is the coverage dishonesty this
 * engine argues against everywhere else.
 */
export function downgradeEncryptedAtRest(findings: Finding[], repo: string): { findings: Finding[]; downgraded: number } {
  const cache = new Map<string, EncryptedShape | undefined>();
  const shapeFor = (rel: string): EncryptedShape | undefined => {
    if (cache.has(rel)) return cache.get(rel);
    let shape: EncryptedShape | undefined;
    try {
      shape = encryptedShapeOf(rel, readText(join(repo, rel)));
    } catch {
      shape = undefined; // unreadable — treat as ordinary, never as suppressed
    }
    cache.set(rel, shape);
    return shape;
  };

  let downgraded = 0;
  const out = findings.map((f) => {
    if (f.category !== "secret" || !f.sink?.file) return f;
    // A scanner that VERIFIED the credential against its provider has evidence
    // no file format can override: a live credential is live.
    if (f.verified) return f;
    const shape = shapeFor(f.sink.file);
    if (!shape) return f;
    downgraded++;
    return {
      ...f,
      severity: "info" as const,
      confidence: "low" as const,
      message: `${f.message} — de-prioritized: ${f.sink.file} is a ${shape.label}, where ciphertext is the point of the file. Check that the ENCRYPTION KEY is not also committed, and that this really is the format it claims.`,
    };
  });
  return { findings: out, downgraded };
}

// ── Credential URIs ──────────────────────────────────────────────────────────

// `scheme://user:secret@host`. Deliberately scheme-agnostic — postgres, mysql,
// mongodb+srv, redis, amqp, ssh, ftp, https, jdbc:… all leak the same way.
const CREDENTIAL_URI = /\b([a-z][a-z0-9+.-]{1,20}):\/\/([^\s:@/'"`]{1,64}):([^\s@/'"`]{1,256})@/gi;

/**
 * Shapes that mean "no secret here": a fully templated component, or a
 * placeholder. The interesting case is a URI where SOME components are
 * templated and the password is not — partial templating is exactly how these
 * survive review, because the line reads as configuration rather than as a
 * credential. So the test is on the password segment ALONE.
 */
const TEMPLATE_ONLY = /^(?:\$\([^)]*\)|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|<[^>]*>|%\([^)]*\)[sd]|%[sdv]|\{[^}]*\}|:[A-Za-z_]\w*|#\{[^}]*\})$/;
const PLACEHOLDER =
  /^(?:x{3,}|\*{3,}|\.{3,}|-+|_+|pass(?:word)?|passwd|secret|changeme|change_me|your[_-]?\w*|my[_-]?\w*|todo|none|null|empty|dummy|example|sample|test|s3cr3t|hunter2|redacted|\[[^\]]*\])$/i;

/** Text files worth reading for a credential URI. Broad on purpose — these leak
 *  from IaC values files and CI YAML far more often than from source. */
const TEXT_EXTS = new Set([
  "yaml",
  "yml",
  "json",
  "toml",
  "ini",
  "cfg",
  "conf",
  "properties",
  "env",
  "tf",
  "tfvars",
  "hcl",
  "xml",
  "md",
  "txt",
  "sh",
  "bash",
  "zsh",
  "js",
  "jsx",
  "ts",
  "tsx",
  "mjs",
  "cjs",
  "py",
  "rb",
  "php",
  "go",
  "java",
  "kt",
  "cs",
  "rs",
  "scala",
  "ex",
  "exs",
  "pl",
  "lua",
  "tpl",
  "template",
]);

/** True when the password component is a real literal rather than a template. */
export function isLiteralSecret(password: string): boolean {
  const p = password.trim();
  if (p.length < 4) return false;
  if (TEMPLATE_ONLY.test(p)) return false;
  if (PLACEHOLDER.test(p)) return false;
  // A value that merely CONTAINS a template is still partly literal, but the
  // literal part is not the whole secret and reporting it invites noise.
  if (/\$\{|\$\(|\{\{|%\(/.test(p)) return false;
  return true;
}

/**
 * Audit a repo for credentials embedded in connection strings.
 *
 * The shape that matters is `scheme://$(user):hunter2@$(host):$(port)/db` —
 * neighbouring components templated, the password not. Partial templating is how
 * these survive review, because the line reads as configuration rather than as a
 * credential, and it is why entropy/format heuristics skip them. So the test is
 * on the password segment ALONE: fully templated or placeholder-shaped stays
 * quiet, a literal does not.
 */
export function auditSecrets(repo: string, prune?: (rel: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const wf of walk(repo)) {
    if (prune?.(wf.rel)) continue;
    if (!TEXT_EXTS.has(extOf(wf.rel))) continue;
    const content = readText(wf.abs);
    if (!content?.includes("://")) continue;
    // A credential inside an encrypted-at-rest file is ciphertext, not a leak.
    if (encryptedShapeOf(wf.rel, content)) continue;

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      CREDENTIAL_URI.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = CREDENTIAL_URI.exec(line)) !== null) {
        const [, scheme, user, password] = m as unknown as [string, string, string, string];
        if (!isLiteralSecret(password)) continue;
        const redacted = `${scheme}://${user}:${"*".repeat(Math.min(password.length, 8))}@…`;
        out.push(
          makeToolFinding({
            tool: "ultrasec",
            category: "secret",
            ident: `credential-uri:${wf.rel}:${i + 1}`,
            title: "Credential embedded in a connection string",
            severity: "high",
            confidence: "medium",
            cwe: "CWE-798",
            message:
              `A ${scheme} connection string at ${wf.rel}:${i + 1} carries a literal password (${redacted}). ` +
              `Neighbouring components may be templated — that is how these survive review, because the line reads as ` +
              `configuration rather than as a credential. Confirm the value is live, then rotate it and move it to a secret ` +
              `store; note that removing it from HEAD does not remove it from history.`,
            file: wf.rel,
            line: i + 1,
            references: [cweUrl("CWE-798")],
          }),
        );
      }
    }
  }
  return out;
}
