# ultrasec toolbox — a self-contained image with the engine + the external
# scanners it orchestrates, so `ultrasec scan` finds them all on PATH. Pinned
# versions (never :latest) for reproducibility + supply-chain safety. Arch is
# detected from the base image so it builds on amd64 and arm64.
FROM node:22-bookworm-slim

ARG TRIVY_VERSION=0.71.1
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.3.8
ARG SEMGREP_VERSION=1.166.0

# python3 (for semgrep) + git (gitleaks/scanners) + curl/ca-certs to fetch binaries.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-pip python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Scanners. Each is a single static binary or a pip package; arch resolved via dpkg.
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in \
    amd64) GL=x64; OSV=amd64 ;; \
    arm64) GL=arm64; OSV=arm64 ;; \
    *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
  esac; \
  # Trivy (official installer, pinned)
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"; \
  # gitleaks (release tarball)
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
  # osv-scanner (release binary — asset name carries no version)
  curl -sSfL -o /usr/local/bin/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV}"; \
  chmod +x /usr/local/bin/osv-scanner; \
  # Semgrep (pip)
  pip3 install --no-cache-dir --break-system-packages "semgrep==${SEMGREP_VERSION}"; \
  trivy --version; gitleaks version; osv-scanner --version; semgrep --version

# The ultrasec engine (committed, zero-dep bundle + skill).
WORKDIR /app
COPY scripts/ultrasec.mjs /app/scripts/ultrasec.mjs
COPY SKILL.md /app/SKILL.md
COPY references /app/references

# Mount the repo to audit at /work.
WORKDIR /work
ENTRYPOINT ["node", "/app/scripts/ultrasec.mjs"]
CMD ["--help"]
