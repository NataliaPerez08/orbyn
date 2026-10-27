#!/usr/bin/env bash
# v1.6 exit-criteria harness — three heterogeneous hosts observed through
# the ingest server, connections backed by evidence, revocation verified
# mid-run (ROADMAP_V2 v1.6; ADR-0002 D3).
#
# Topology: the ingest server runs on the host, bound to the lab bridge
# (192.0.2.1:7780 — binding beyond loopback is deliberate here: the
# 192.0.2.0/24 bridge is isolated TEST-NET space). The agents run on
# web-01 (Ubuntu 24.04), api-01 (Ubuntu 22.04) and db-01 (Ubuntu 20.04)
# — three heterogeneous OSes. legacy-01 stays agentless, so the lab
# covers both collection modes.
#
# The orbyn binary must run on Ubuntu 20.04 (glibc 2.31); a binary built
# on a newer distribution may not. The script checks this on db-01 first
# and tells you if the binary is too new.
#
# With --service the agent is installed as a systemd service on each VM
# (sampling plus a 5-minute sync timer) instead of one-shot samples —
# the setup for the 7-day v1.5 observation, validated afterwards with
# ./check-observation.sh.
#
# Requires: the lab up (./start-lab.sh) and an orbyn binary
# (ORBYN_BIN=... to point at one).
set -euo pipefail
cd "$(dirname "$0")"

ORBYN="${ORBYN_BIN:-orbyn}"
command -v "$ORBYN" >/dev/null || { echo "orbyn not found (set ORBYN_BIN=/path/to/orbyn)" >&2; exit 1; }
ORBYN=$(readlink -f "$(command -v "$ORBYN")")

SSH_OPTS=(-i lab_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
SERVER_DB=server.db
BIND=192.0.2.1:7780
URL=http://192.0.2.1:7780/v1/ingest
VMS=("web-01 192.0.2.11" "api-01 192.0.2.12" "db-01 192.0.2.13")
SERVICE_MODE=0
[ "${1:-}" = "--service" ] && SERVICE_MODE=1

PASS=0; FAIL=0
check() {
  if [ "$2" = 1 ]; then PASS=$((PASS + 1)); echo "  PASS  $1"
  else FAIL=$((FAIL + 1)); echo "  FAIL  $1"; fi
}

asset_id() { echo "${1//./-}"; }

server_samples() { # ip -> sample_count on the server db
  "$ORBYN" --db "$SERVER_DB" agent report --asset-ip "$1" --format json 2>/dev/null \
    | grep -oE '"sample_count": *[0-9]+' | grep -oE '[0-9]+'
}

# --- sanity: lab reachable, binary runs on the oldest guest -----------
ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 true 2>/dev/null \
  || { echo "lab not reachable — run ./start-lab.sh first" >&2; exit 1; }
scp -q "${SSH_OPTS[@]}" "$ORBYN" deploy@192.0.2.13:/tmp/orbyn
ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 /tmp/orbyn --version >/dev/null 2>&1 \
  || { echo "the orbyn binary does not run on db-01 (Ubuntu 20.04, glibc 2.31) —" \
        "build against an older toolchain and retry" >&2; exit 1; }

# --- ingest server on the host ----------------------------------------
mkdir -p logs
rm -f "$SERVER_DB"
echo "== starting the ingest server on $BIND =="
"$ORBYN" --db "$SERVER_DB" server run --bind "$BIND" > logs/server.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
UP=0
for _ in $(seq 1 20); do
  # Any HTTP response (404/405 on GET) proves the listener is up.
  if curl -s -o /dev/null "$URL"; then UP=1; break; fi
  sleep 0.5
done
[ "$UP" = 1 ] || { echo "ingest server did not come up (see logs/server.log)" >&2; exit 1; }

install_service() { # ip token
  local ip=$1 token=$2
  ssh "${SSH_OPTS[@]}" "deploy@$ip" "sudo mkdir -p /var/lib/orbyn /etc/orbyn
    echo \"ORBYN_SYNC_TOKEN=$token\" | sudo tee /etc/orbyn/sync.env >/dev/null
    sudo chmod 600 /etc/orbyn/sync.env
    sudo tee /usr/local/bin/orbyn-agent-sync.sh >/dev/null <<'SCRIPT'
#!/bin/sh
exec /usr/local/bin/orbyn agent sync --url $URL --asset-ip $ip \\
  --db /var/lib/orbyn/agent.db
SCRIPT
    sudo chmod 755 /usr/local/bin/orbyn-agent-sync.sh
    sudo tee /etc/systemd/system/orbyn-agent.service >/dev/null <<'UNIT'
[Unit]
Description=Orbyn observation agent
After=network-online.target
[Service]
ExecStart=/usr/local/bin/orbyn agent run --db /var/lib/orbyn/agent.db --asset-ip $ip
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
    sudo tee /etc/systemd/system/orbyn-agent-sync.service >/dev/null <<'UNIT'
[Unit]
Description=Ship Orbyn agent samples to the ingest server
[Service]
Type=oneshot
EnvironmentFile=/etc/orbyn/sync.env
ExecStart=/usr/local/bin/orbyn-agent-sync.sh
UNIT
    sudo tee /etc/systemd/system/orbyn-agent-sync.timer >/dev/null <<'UNIT'
[Unit]
Description=Run the Orbyn sync every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
    sudo systemctl daemon-reload
    sudo systemctl enable --now orbyn-agent.service orbyn-agent-sync.timer"
}

# --- enroll each VM, sample, sync --------------------------------------
declare -A TOKENS
for spec in "${VMS[@]}"; do
  read -r name ip <<<"$spec"
  echo "== $name ($ip): install agent, enroll, sample, sync =="
  scp -q "${SSH_OPTS[@]}" "$ORBYN" "deploy@$ip:/tmp/orbyn"
  ssh "${SSH_OPTS[@]}" "deploy@$ip" "sudo install -m 755 /tmp/orbyn /usr/local/bin/orbyn"

  TOKENS[$ip]=$("$ORBYN" --db "$SERVER_DB" server enroll --asset-ip "$ip" 2>/dev/null)
  [ -n "${TOKENS[$ip]}" ] || { echo "  enrollment returned no token" >&2; exit 1; }

  if [ "$SERVICE_MODE" = 1 ]; then
    install_service "$ip" "${TOKENS[$ip]}"
    check "$name: agent service + sync timer installed" 1
  else
    ssh "${SSH_OPTS[@]}" "deploy@$ip" "rm -f /tmp/orbyn-agent.db
      for _ in 1 2 3; do /usr/local/bin/orbyn agent run --once --asset-ip $ip --db /tmp/orbyn-agent.db; sleep 1; done"
    ssh "${SSH_OPTS[@]}" "deploy@$ip" \
      "/usr/local/bin/orbyn agent sync --url $URL --asset-ip $ip --token ${TOKENS[$ip]} --db /tmp/orbyn-agent.db"
    check "$name: 3 samples synced to the server" 1
  fi
done

# --- criterion 1: three heterogeneous hosts observed -------------------
echo "== verifying observations on the server =="
OBSERVED=0
for spec in "${VMS[@]}"; do
  read -r name ip <<<"$spec"
  N=$(server_samples "$ip")
  if [ -n "$N" ] && [ "$N" -gt 0 ]; then
    OBSERVED=$((OBSERVED + 1))
  else
    echo "  (no samples on the server for $ip)" >&2
  fi
done
if [ "$OBSERVED" -eq 3 ]; then
  check "three heterogeneous hosts observed through the server (3/3)" 1
else
  check "three heterogeneous hosts observed through the server ($OBSERVED/3)" 0
fi

# --- criterion 2: connections backed by evidence -----------------------
# connections CSV columns: asset_id,proto,local_ip,local_port,remote_ip,remote_port,process
echo "== verifying connection evidence =="
CONNS=$("$ORBYN" --db "$SERVER_DB" connections 192.0.2.12 --format csv 2>/dev/null || true)
echo "$CONNS" | grep -q "192\.0\.2\.13,5432" \
  && check "api-01 -> db-01:5432 observed with evidence" 1 \
  || check "api-01 -> db-01:5432 observed with evidence" 0
echo "$CONNS" | grep -q "192\.0\.2\.13,6379" \
  && check "api-01 -> db-01:6379 observed with evidence" 1 \
  || check "api-01 -> db-01:6379 observed with evidence" 0
CONNS=$("$ORBYN" --db "$SERVER_DB" connections 192.0.2.11 --format csv 2>/dev/null || true)
echo "$CONNS" | grep -q "192\.0\.2\.12,8080" \
  && check "web-01 -> api-01:8080 observed with evidence" 1 \
  || check "web-01 -> api-01:8080 observed with evidence" 0
if [ "$SERVICE_MODE" = 0 ]; then
  # One-shot samples carry the connection snapshot; the graph reconciles
  # them into edges. (In service mode the first timer sync may not have
  # fired yet.)
  "$ORBYN" --db "$SERVER_DB" graph --format csv 2>/dev/null | grep -q "192-0-2-12,192-0-2-13" \
    && check "dependency graph has api-01 -> db-01 edges" 1 \
    || check "dependency graph has api-01 -> db-01 edges" 0
fi

# --- criterion 3: revocation verified mid-run --------------------------
echo "== revoking db-01 and verifying the sync is refused =="
DB_ID=$(asset_id 192.0.2.13)
"$ORBYN" --db "$SERVER_DB" server revoke "$DB_ID" >/dev/null
BEFORE=$(server_samples 192.0.2.13)
if [ "$SERVICE_MODE" = 1 ]; then
  # The oneshot sync service exits non-zero when the server refuses it.
  if ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
      "sudo systemctl start orbyn-agent-sync.service" 2>/dev/null; then
    check "revoked db-01 sync is refused" 0
  else
    check "revoked db-01 sync is refused" 1
  fi
else
  ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
    "/usr/local/bin/orbyn agent run --once --asset-ip 192.0.2.13 --db /tmp/orbyn-agent.db"
  if ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
      "/usr/local/bin/orbyn agent sync --url $URL --asset-ip 192.0.2.13 --token ${TOKENS[192.0.2.13]} --db /tmp/orbyn-agent.db" 2>/dev/null; then
    check "revoked db-01 sync is refused" 0
  else
    check "revoked db-01 sync is refused" 1
  fi
fi
AFTER=$(server_samples 192.0.2.13)
if [ "$BEFORE" = "$AFTER" ]; then
  check "server sample count for db-01 unchanged after revocation ($AFTER)" 1
else
  check "server sample count for db-01 unchanged after revocation ($BEFORE -> $AFTER)" 0
fi
if [ "$SERVICE_MODE" = 1 ]; then
  BUFFERED=$(ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
    "sudo /usr/local/bin/orbyn agent report --asset-ip 192.0.2.13 --format json --db /var/lib/orbyn/agent.db 2>/dev/null | grep -oE '\"sample_count\": *[0-9]+' | grep -oE '[0-9]+' | head -1" || true)
else
  BUFFERED=$(ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
    "/usr/local/bin/orbyn agent report --asset-ip 192.0.2.13 --format json --db /tmp/orbyn-agent.db 2>/dev/null | grep -oE '\"sample_count\": *[0-9]+' | grep -oE '[0-9]+' | head -1" || true)
fi
if [ -n "$BUFFERED" ] && [ "$BUFFERED" != "0" ]; then
  check "db-01 keeps buffering locally after revocation ($BUFFERED)" 1
else
  check "db-01 keeps buffering locally after revocation" 0
fi

# Leave the lab usable: re-enroll db-01 with a fresh token.
echo "== re-enrolling db-01 so the lab stays usable =="
NEW_TOKEN=$("$ORBYN" --db "$SERVER_DB" server enroll --asset-ip 192.0.2.13 2>/dev/null)
if [ "$SERVICE_MODE" = 1 ]; then
  ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
    "echo 'ORBYN_SYNC_TOKEN=$NEW_TOKEN' | sudo tee /etc/orbyn/sync.env >/dev/null"
  echo "  (db-01 re-enrolled; the timer picks the new token up on the next run)"
else
  ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
    "/usr/local/bin/orbyn agent sync --url $URL --asset-ip 192.0.2.13 --token $NEW_TOKEN --db /tmp/orbyn-agent.db" \
    && echo "  (db-01 re-enrolled and synced again)" \
    || echo "  (db-01 re-enrolled; sync will retry from the buffer later)"
fi

echo
echo "v1.6 exit criteria: $PASS passed, $FAIL failed"
echo "server database: $SERVER_DB (inspect with: $ORBYN --db $SERVER_DB assets)"
[ "$FAIL" -eq 0 ]
