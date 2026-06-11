#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
VERSION="${SSHMAP_VERSION:-$(grep '^version' "${ROOT}/Cargo.toml" | head -1 | cut -d'"' -f2)}"

mkdir -p "${DIST}"

echo "Building sshmap ${VERSION} release binary..."
cargo build --release --manifest-path "${ROOT}/Cargo.toml"
cp "${ROOT}/target/release/sshmap" "${DIST}/sshmap"

if command -v nfpm >/dev/null 2>&1; then
  export SSHMAP_VERSION="${VERSION}"
  nfpm package --config "${ROOT}/packaging/nfpm.yaml" --target "${DIST}" --packager deb
  nfpm package --config "${ROOT}/packaging/nfpm.yaml" --target "${DIST}" --packager rpm
  echo "Packages written to ${DIST}"
else
  echo "nfpm not found; binary only written to ${DIST}/sshmap"
  echo "Install nfpm from https://nfpm.goreleaser.com/ to build deb/rpm packages."
fi

(cd "${DIST}" && sha256sum sshmap > SHA256SUMS)
echo "SHA256SUMS written to ${DIST}/SHA256SUMS"
