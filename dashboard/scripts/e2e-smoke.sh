#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

INDEX_FILE="$(mktemp "${TMPDIR:-/tmp}/sshmap-dashboard-index.XXXXXX.html")"

npm run build
npm run preview -- --host 127.0.0.1 --port 4173 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$INDEX_FILE"' EXIT

READY=0
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:4173/" >"$INDEX_FILE" 2>/dev/null; then
    READY=1
    break
  fi
  sleep 1
done

if [[ "$READY" -ne 1 ]]; then
  echo "Dashboard preview did not become ready on http://127.0.0.1:4173/" >&2
  exit 1
fi

grep -q "SSHMap Dashboard" "$INDEX_FILE"
echo "Dashboard shell smoke test passed."
