#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

npm run build
npm run preview -- --host 127.0.0.1 --port 4173 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:4173/" >/tmp/sshmap-dashboard-index.html 2>/dev/null; then
    break
  fi
  sleep 1
done

grep -q "SSHMap Dashboard" /tmp/sshmap-dashboard-index.html
echo "Dashboard shell smoke test passed."
