#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 SHA256SUMS [gpg-key-id]" >&2
  exit 1
fi

CHECKSUMS_FILE="$1"
GPG_KEY="${2:-}"

if [[ ! -f "${CHECKSUMS_FILE}" ]]; then
  echo "checksum file not found: ${CHECKSUMS_FILE}" >&2
  exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg not found; skipping signature" >&2
  exit 0
fi

if [[ -n "${GPG_KEY}" ]]; then
  gpg --batch --yes --local-user "${GPG_KEY}" --detach-sign --armor "${CHECKSUMS_FILE}"
else
  gpg --batch --yes --detach-sign --armor "${CHECKSUMS_FILE}"
fi

echo "Signed ${CHECKSUMS_FILE} -> ${CHECKSUMS_FILE}.asc"
