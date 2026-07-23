# ultrasec toolbox — a self-contained image with the engine + the external
# scanners it orchestrates, so `ultrasec scan` finds them all on PATH. Every
# scanner installs its LATEST release by default (accepting the reproducibility
# trade-off for always-current CVE/rule coverage) — image freshness is therefore
# the freshness of the last `docker compose build`; run
# `docker compose build --no-cache` to pick up new releases (a cached layer
# otherwise keeps whatever was latest at the last build). Each ARG below is an
# optional override: pass `--build-arg TRIVY_VERSION=0.71.1` (etc.) to pin a
# specific tool to a specific release when reproducibility matters more than
# freshness. Arch is detected from the base image so it builds on amd64 and
# arm64.
FROM node:22-bookworm-slim

# Empty (default) ⇒ install each tool's latest release. Set a version to pin.
ARG TRIVY_VERSION=
ARG GITLEAKS_VERSION=
ARG OSV_VERSION=
ARG SEMGREP_VERSION=
ARG GOSEC_VERSION=
ARG HADOLINT_VERSION=
ARG BANDIT_VERSION=
ARG CHECKOV_VERSION=
ARG GRYPE_VERSION=
ARG SYFT_VERSION=
ARG PIP_AUDIT_VERSION=

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
  # Trivy (official installer): the installer resolves the latest release
  # itself when no tag is given, so an empty ARG needs no extra API call.
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin ${TRIVY_VERSION:+v$TRIVY_VERSION}; \
  # grype (official Anchore installer — same "no tag = latest" convention)
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin ${GRYPE_VERSION:+v$GRYPE_VERSION}; \
  # syft (official Anchore installer — SBOM generator, pairs with grype)
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin ${SYFT_VERSION:+v$SYFT_VERSION}; \
  # gitleaks (release tarball — asset name embeds the version, so an empty ARG
  # resolves the real tag from the GitHub API first, then downloads by tag).
  GITLEAKS_VERSION="${GITLEAKS_VERSION:-$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')}"; \
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks; \
  # osv-scanner (release binary — asset name carries no version, so GitHub's
  # own `/latest/download/<asset>` alias resolves it without an API call).
  if [ -n "${OSV_VERSION}" ]; then OSV_URL="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV}"; \
  else OSV_URL="https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${OSV}"; fi; \
  curl -sSfL -o /usr/local/bin/osv-scanner "$OSV_URL"; \
  chmod +x /usr/local/bin/osv-scanner; \
  # gosec (release tarball — asset name embeds the version, same as gitleaks).
  GOSEC_VERSION="${GOSEC_VERSION:-$(curl -fsSL https://api.github.com/repos/securego/gosec/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')}"; \
  curl -sSfL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GSA}.tar.gz" \
    | tar -xz -C /usr/local/bin gosec; \
  # hadolint (single release binary). Upstream renamed the linux asset from
  # `hadolint-Linux-<arch>` (releases <=2.12.x) to `hadolint-linux-<arch>`
  # (releases >=2.13.1, the first stable tag after the rename), so a fixed
  # asset name only works for one era. The empty-ARG (latest) branch always
  # resolves to a current release via GitHub's `/latest/download/` alias, so
  # it only ever needs the lowercase name; a pin, though, can target either
  # era, so it tries today's lowercase asset first and falls back to the
  # pre-2.13 capitalized one on a 404.
  if [ -n "${HADOLINT_VERSION}" ]; then \
    HAD_BASE="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}"; \
    curl -sSfL -o /usr/local/bin/hadolint "${HAD_BASE}/hadolint-linux-${HAD}" \
      || curl -sSfL -o /usr/local/bin/hadolint "${HAD_BASE}/hadolint-Linux-${HAD}"; \
  else \
    curl -sSfL -o /usr/local/bin/hadolint "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-linux-${HAD}"; \
  fi; \
  chmod +x /usr/local/bin/hadolint; \
  # Semgrep + bandit + checkov + pip-audit (pip): an empty ARG drops the
  # `==version` pin entirely, so pip resolves each package's latest release.
  pip3 install --no-cache-dir --break-system-packages \
    "semgrep${SEMGREP_VERSION:+==$SEMGREP_VERSION}" "bandit${BANDIT_VERSION:+==$BANDIT_VERSION}" \
    "checkov${CHECKOV_VERSION:+==$CHECKOV_VERSION}" "pip-audit${PIP_AUDIT_VERSION:+==$PIP_AUDIT_VERSION}"; \
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
