import { readText, walk } from "./walk.js";
import type { Finding, Severity } from "./types.js";
import { makeToolFinding } from "./tools/normalize.js";

// Cloud / Kubernetes / IaC misconfiguration — the static, code-level half of
// what checkov covers, but ZERO-dependency so it fires even when checkov isn't
// installed (and folds into checkov's finding via the correlator when it is).
//
// LINE / per-file scan, same contract as src/webconfig.ts and src/actions.ts:
// every finding is a CANDIDATE grounded on a resolvable [file:line], category
// `config`, the CWE is what the coverage packs key on. The DEEPER, reachability
// half (does this SSRF actually reach the metadata endpoint? is this IAM role
// really over-privileged in context?) stays manual — see `investigate --lens cloud`.

export interface CloudShape {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  note: string;
}

/** The shapes, kept as data so the reference and the engine cannot drift. */
export const CLOUD_SHAPES: Record<string, CloudShape> = {
  "k8s-privileged": {
    id: "k8s-privileged",
    title: "Privileged container",
    severity: "high",
    cwe: "CWE-250",
    note: "`privileged: true` gives the container ~root on the node — a container escape becomes a host takeover. Drop it and grant only the specific capabilities needed.",
  },
  "k8s-host-namespace": {
    id: "k8s-host-namespace",
    title: "Container shares a host namespace / path",
    severity: "high",
    cwe: "CWE-250",
    note: "`hostNetwork`/`hostPID`/`hostIPC: true` or a `hostPath` mount breaks the container boundary — the pod can reach the node's network, processes or filesystem.",
  },
  "k8s-privesc": {
    id: "k8s-privesc",
    title: "Privilege escalation allowed / runs as root",
    severity: "medium",
    cwe: "CWE-269",
    note: "`allowPrivilegeEscalation: true` (or `runAsNonRoot: false`) lets a process gain more privileges than its parent. Set `allowPrivilegeEscalation: false` and `runAsNonRoot: true`.",
  },
  "iam-wildcard": {
    id: "iam-wildcard",
    title: "IAM policy allows Action:* on Resource:*",
    severity: "high",
    cwe: "CWE-732",
    note: "An Allow with `Action: *` and `Resource: *` is full administrative access — the opposite of least privilege. Scope both to what the principal actually needs.",
  },
  "iam-public-principal": {
    id: "iam-public-principal",
    title: "Resource policy grants access to everyone (Principal:*)",
    severity: "high",
    cwe: "CWE-732",
    note: '`"Effect": "Allow"` with `"Principal": "*"` exposes the resource to any AWS account / the public. Restrict the principal.',
  },
  "open-ingress": {
    id: "open-ingress",
    title: "Ingress open to the whole internet (0.0.0.0/0)",
    severity: "medium",
    cwe: "CWE-284",
    note: "A security-group / firewall ingress from `0.0.0.0/0` (or `::/0`) exposes the port to everyone. Restrict the CIDR, especially for admin ports (22/3389/db).",
  },
  "public-storage": {
    id: "public-storage",
    title: "Object storage made public",
    severity: "high",
    cwe: "CWE-732",
    note: "A `public-read`/`public-read-write` ACL (or a public bucket setting) exposes stored objects to anyone. Keep buckets private and front them with signed URLs.",
  },
  "iac-unencrypted": {
    id: "iac-unencrypted",
    title: "Storage / database encryption disabled",
    severity: "high",
    cwe: "CWE-311",
    note: "`encrypted = false` / `storage_encrypted = false` leaves the volume, bucket or database unencrypted at rest — anyone who reaches the underlying storage (a snapshot, a stolen disk, a misdelegated role) reads it in the clear.",
  },
  "iac-public-instance": {
    id: "iac-public-instance",
    title: "Database / instance publicly accessible",
    severity: "high",
    cwe: "CWE-284",
    note: "`publicly_accessible = true` gives the instance a public endpoint. Combined with a weak password or an open security group it is directly reachable from the internet.",
  },
  "iac-hardcoded-secret": {
    id: "iac-hardcoded-secret",
    title: "Credential hardcoded in infrastructure code",
    severity: "high",
    cwe: "CWE-798",
    note: "A password/secret/token written as a literal in IaC lands in git history and in every plan/state file. Use a variable bound to a secret manager (vault, SSM, Key Vault) instead.",
  },
  "cloud-metadata": {
    id: "cloud-metadata",
    title: "Cloud instance-metadata endpoint referenced in code",
    severity: "low",
    cwe: "CWE-918",
    note: "A hardcoded link-local metadata endpoint (169.254.169.254 / metadata.google.internal). Legitimate for SDKs, but it is also the SSRF prize — confirm no user-controlled URL can reach it (see `investigate --lens cloud`).",
  },
};

interface Line {
  n: number;
  text: string;
}

function lines(content: string): Line[] {
  return content.split(/\r?\n/).map((text, i) => ({ n: i + 1, text }));
}

function extOf(rel: string): string {
  const i = rel.lastIndexOf(".");
  return i === -1 ? "" : rel.slice(i + 1).toLowerCase();
}

const CODE = new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "py", "go", "java", "kt", "scala", "php", "rb", "cs"]);
// Infrastructure-as-code proper. The resource-shaped rules (encryption off,
// public instance, hardcoded credential) are gated to THESE only: a credential
// in application code is gitleaks' job — it has 221 tuned rules where this
// module has one crude regex — and calling a PHP constant "infrastructure code"
// mislabels the finding. Measured on DVWA, where the ungated rule produced 20
// mislabeled hits in .php files.
const IAC_EXTS = new Set(["yaml", "yml", "json", "tf", "tfvars", "hcl", "template"]);
// The metadata-endpoint shape is the one rule that IS about application code.
const SCAN = new Set([...IAC_EXTS, ...CODE]);

function hit(rel: string, line: number, shape: CloudShape, evidence: string): Finding {
  return makeToolFinding({
    tool: "ultrasec",
    category: "config",
    ident: `cloud:${shape.id}:${rel}:${line}`,
    title: `Cloud/IaC — ${shape.title}`,
    severity: shape.severity,
    message: `${shape.note}\n\nEvidence: \`${evidence.trim().slice(0, 160)}\``,
    file: rel,
    line,
    cwe: shape.cwe,
  });
}

function lineOf(content: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content[i] === "\n") n++;
  return n;
}

const METADATA_RE = /169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/;

// EGRESS to 0.0.0.0/0 is the normal, usually-benign case: "this host may reach
// the internet". Only INGRESS from 0.0.0.0/0 exposes a port to the world. The
// CIDR line itself looks identical in both, so the direction has to come from
// the enclosing rule — found by walking BACK to the nearest direction marker
// (`type = "egress"` / `direction = "EGRESS"` on a *_security_group_rule or
// firewall, or an `egress {` / `ingress {` block opener inside a security group).
// Measured on TerraGoat, this is the difference between one true positive and
// one false positive on the same repo.
const EGRESS_MARK = /\btype\s*=\s*["']egress["']|\bdirection\s*=\s*["']EGRESS["']|(?:^|\s)egress\s*(?:\{|=)/i;
const INGRESS_MARK = /\btype\s*=\s*["']ingress["']|\bdirection\s*=\s*["']INGRESS["']|(?:^|\s)ingress\s*(?:\{|=)/i;
const DIRECTION_LOOKBACK = 25;

// A credential assigned in IaC. The NAME half is deliberately narrow (a bare
// `key =` is an object key half the time), and the VALUE half must be a literal:
// `password = var.db_password` / `"${var.x}"` / `data.vault…` is the CORRECT
// pattern and must never be flagged — that is the whole point of the variable.
const IAC_SECRET_RE = /\b(?:\w*password|\w*secret|\w*token|access_key|secret_key|api_key|private_key|passwd|credential)\w*\s*=\s*/i;
const INTERPOLATED = /^["']?\$\{|(?:^|=\s*)(?:var|local|data|module|each|jsondecode|file)\b/i;

function isLiteralSecret(text: string): boolean {
  const m = /=\s*(.+?)\s*$/.exec(text);
  const rhs = (m?.[1] ?? "").trim();
  if (!rhs || INTERPOLATED.test(rhs)) return false;
  const lit = /^["']([^"']*)["']/.exec(rhs);
  if (!lit) return false; // not a quoted literal (a reference, a function call…)
  const value = lit[1] ?? "";
  // Empty, a pure interpolation, or a too-short placeholder isn't a credential.
  return value.length >= 3 && !value.includes("${");
}

/** True when the nearest preceding direction marker says this rule is egress. */
function isEgressRule(ls: Line[], line: number): boolean {
  for (let i = line - 1; i >= Math.max(0, line - 1 - DIRECTION_LOOKBACK); i--) {
    const t = ls[i]?.text ?? "";
    if (EGRESS_MARK.test(t)) return true;
    if (INGRESS_MARK.test(t)) return false;
  }
  return false; // no marker found — keep the finding (fail toward reporting)
}

/** Audit a repo for cloud / K8s / IaC misconfiguration. Returns candidates. */
export function auditCloud(repo: string, prune?: (rel: string) => boolean): Finding[] {
  const out: Finding[] = [];
  for (const wf of walk(repo)) {
    if (prune?.(wf.rel)) continue;
    const ext = extOf(wf.rel);
    if (!SCAN.has(ext)) continue;
    const content = readText(wf.abs);
    if (!content) continue;
    const rel = wf.rel;
    const ls = lines(content);

    // Cloud metadata endpoint — the one shape that is about application code too.
    for (const l of ls) if (METADATA_RE.test(l.text)) out.push(hit(rel, l.n, CLOUD_SHAPES["cloud-metadata"]!, l.text));

    // Everything below describes an INFRASTRUCTURE resource, so it only applies
    // to infrastructure files (see IAC_EXTS).
    if (!IAC_EXTS.has(ext)) continue;

    // Kubernetes security context — only in a file that actually looks like a
    // manifest (has both apiVersion: and kind:), so a stray `privileged: true`
    // in unrelated YAML isn't flagged.
    const isK8s = /(^|\n)\s*apiVersion:/.test(content) && /(^|\n)\s*kind:/.test(content);
    if (isK8s) {
      for (const l of ls) {
        if (/^\s*privileged:\s*true\b/i.test(l.text)) out.push(hit(rel, l.n, CLOUD_SHAPES["k8s-privileged"]!, l.text));
        if (/^\s*host(?:Network|PID|IPC):\s*true\b/i.test(l.text) || /^\s*hostPath:/i.test(l.text))
          out.push(hit(rel, l.n, CLOUD_SHAPES["k8s-host-namespace"]!, l.text));
        if (/^\s*allowPrivilegeEscalation:\s*true\b/i.test(l.text) || /^\s*runAsNonRoot:\s*false\b/i.test(l.text))
          out.push(hit(rel, l.n, CLOUD_SHAPES["k8s-privesc"]!, l.text));
      }
    }

    // IAM policy documents (JSON / Terraform). Action:* + Resource:* in the same
    // file is full-admin; Principal:* under Allow is a public resource policy.
    const hasActionStar = /"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.test(content);
    const hasResourceStar = /"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.test(content);
    if (hasActionStar && hasResourceStar) {
      const m = /"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])/.exec(content);
      if (m) out.push(hit(rel, lineOf(content, m.index), CLOUD_SHAPES["iam-wildcard"]!, m[0]));
    }
    const allowPublic = /"Effect"\s*:\s*"Allow"/.test(content) && /"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})/.test(content);
    if (allowPublic) {
      const m = /"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})/.exec(content);
      if (m) out.push(hit(rel, lineOf(content, m.index), CLOUD_SHAPES["iam-public-principal"]!, m[0]));
    }

    // Line-level IaC shapes: open ingress CIDR and public storage ACL.
    for (const l of ls) {
      if (
        (/(?:cidr_blocks|cidr_ip|source_ranges|CidrIp)\b[^\n]*(?:0\.0\.0\.0\/0|::\/0)/i.test(l.text) ||
          /^\s*-?\s*["']?(?:0\.0\.0\.0\/0|::\/0)["']?\s*$/.test(l.text)) &&
        !isEgressRule(ls, l.n)
      )
        out.push(hit(rel, l.n, CLOUD_SHAPES["open-ingress"]!, l.text));
      if (/\bacl\b[^\n]*["']public-read(?:-write)?["']|["']public-read(?:-write)?["']/i.test(l.text) && /\bacl\b/i.test(l.text))
        out.push(hit(rel, l.n, CLOUD_SHAPES["public-storage"]!, l.text));
      // Encryption switched OFF explicitly (an absent setting is a default we
      // can't read from one line, so only the explicit `false` is a finding).
      if (/\b(?:storage_encrypted|encrypted|encryption_enabled|encrypt_at_rest)\s*=\s*false\b/i.test(l.text))
        out.push(hit(rel, l.n, CLOUD_SHAPES["iac-unencrypted"]!, l.text));
      if (/\bpublicly_accessible\s*=\s*true\b/i.test(l.text)) out.push(hit(rel, l.n, CLOUD_SHAPES["iac-public-instance"]!, l.text));
      if (IAC_SECRET_RE.test(l.text) && isLiteralSecret(l.text)) out.push(hit(rel, l.n, CLOUD_SHAPES["iac-hardcoded-secret"]!, l.text));
    }
  }
  return out;
}
