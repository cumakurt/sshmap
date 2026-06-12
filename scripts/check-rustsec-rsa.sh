#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Checking for RUSTSEC-2023-0071 (rsa via russh)..."
if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "Installing cargo-audit..."
  cargo install cargo-audit --locked
fi

if cargo audit 2>&1 | grep -q 'RUSTSEC-2023-0071'; then
  echo "ADVISORY STILL PRESENT: RUSTSEC-2023-0071"
  echo "Action: prefer --transport openssh; watch russh/rsa releases."
  echo "If a fixed release is available, remove the ignore in .cargo/audit.toml and update dependencies."
  exit 1
fi

echo "RUSTSEC-2023-0071 not reported — consider removing the ignore from .cargo/audit.toml."
exit 0
