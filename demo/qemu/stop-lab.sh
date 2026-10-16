#!/usr/bin/env bash
# Stop the demo lab VMs. The bridge and NAT rule stay behind for the next run.
set -euo pipefail
cd "$(dirname "$0")"

shopt -s nullglob
pidfiles=(*.pid)
if [ ${#pidfiles[@]} -eq 0 ]; then
  echo "no VMs running"
  exit 0
fi
for pidfile in "${pidfiles[@]}"; do
  name=${pidfile%.pid}
  if kill "$(cat "$pidfile")" 2>/dev/null; then
    echo "stopped $name"
  fi
  rm -f "$pidfile"
done
