# ultrasec toolbox — a self-contained image with the engine + the external
# scanners it orchestrates, so `ultrasec scan` finds them all on PATH. Pinned
# versions (never :latest) for reproducibility + supply-chain safety. Arch is
# detected from the base image so it builds on amd64 and arm64.
FROM node:22-bookworm-slim

ARG TRIVY_VERSION=0.71.1
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.3.8
ARG SEMGREP_VERSION=1.166.0
ARG GOSEC_VERSION=2.21.4
ARG HADOLINT_VERSION=2.12.0
ARG BANDIT_VERSION=1.8.6
ARG CHECKOV_VERSION=3.2.0
ARG GRYPE_VERSION=0.116.0
ARG SYFT_VERSION=1.49.0
ARG PIP_AUDIT_VERSION=2.10.1

# python3 (for semgrep/bandit/checkov/pip-audit) + git (gitleaks/scanners) +
# curl/ca-certs + gawk (package-checker needs awk; bookworm-slim ships mawk by
# default — gawk is small insurance against a mawk-specific incompatibility).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git gawk python3 python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Scanners. Each is a single static binary or a pip package; arch resolved via dpkg.
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) GL=x64; OSV=amd64; GSA=amd64; HAD=x86_64 ;; \
    arm64) GL=arm64; OSV=arm64; GSA=arm64; HAD=arm64 ;; \
    *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
  esac; \
  # Trivy (official installer, pinned)
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"; \
  # grype (official Anchore installer, pinned — same pattern as trivy)
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin "v${GRYPE_VERSION}"; \
  # syft (official Anchore installer, pinned — SBOM generator, pairs with grype)
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin "v${SYFT_VERSION}"; \
  # gitleaks (release tarball)
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
  # osv-scanner (release binary — asset name carries no version)
  curl -sSfL -o /usr/local/bin/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV}"; \
  chmod +x /usr/local/bin/osv-scanner; \
  # gosec (release tarball)
  curl -sSfL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GSA}.tar.gz" \
    | tar -xz -C /usr/local/bin gosec; \
  # hadolint (single release binary)
  curl -sSfL -o /usr/local/bin/hadolint \
    "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HAD}"; \
  chmod +x /usr/local/bin/hadolint; \
  # Semgrep + bandit + checkov + pip-audit (pip)
  pip3 install --no-cache-dir --break-system-packages \
    "semgrep==${SEMGREP_VERSION}" "bandit==${BANDIT_VERSION}" "checkov==${CHECKOV_VERSION}" "pip-audit==${PIP_AUDIT_VERSION}"; \
  trivy --version; gitleaks version; osv-scanner --version; semgrep --version; gosec --version; hadolint --version; bandit --version; checkov --version; \
  grype version; syft version; pip-audit --version

# Not baked in (deliberately — they're per-run/network-fetched state, not
# pinned binaries, and would bloat the image): the grype vulnerability DB and
# package-checker's GHSA/OSV feeds. Warm them once for air-gapped/offline use
# (persist the result under a bind-mounted/volume dir so it survives past the
# container): `grype db update`; package-checker's vendored script accepts
# `--fetch-all <dir>` (see skills/ultrasec/references/tools.md for the full
# offline flow, including where the vendored script materializes on disk).

# The ultrasec engine (committed, zero-dep bundle + skill).
WORKDIR /app
COPY scripts/ultrasec.mjs /app/scripts/ultrasec.mjs
COPY skills/ultrasec/SKILL.md /app/SKILL.md
COPY skills/ultrasec/references /app/references

# Mount the repo to audit at /work.
WORKDIR /work
ENTRYPOINT ["node", "/app/scripts/ultrasec.mjs"]
CMD ["--help"]
