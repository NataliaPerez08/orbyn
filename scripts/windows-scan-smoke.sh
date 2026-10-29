#!/usr/bin/env bash
# Functional network-discovery tests for the Windows `orbyn.exe`.
#
# Unlike windows-smoke.sh (offline DB surface), these checks run the *real*
# native TCP-connect sweep against live listeners and real segments — no fake
# external tools. A local listener is started on every interface so the scan
# has a known open port to find, and the sweep is pointed at:
#   * a single loopback host,
#   * a loopback CIDR (multi-host segment),
#   * the real eth0 /24 segment.
# It also covers `auto` collector selection, the recorded job, re-scan
# reconciliation and the oversized-scope guard.
#
# The Windows binary scans for real under Wine (winsock maps to host sockets):
# the same script runs on Windows natively with ORBYN_WINE=.
#
# Usage: windows-scan-smoke.sh [path/to/orbyn.exe]
# Env:   ORBYN_EXE   path to the .exe (arg wins)
#        ORBYN_WINE  runner prefix (defaults to `wine` if on PATH, else empty)
#        ORBYN_SCAN_CIDR  override the LAN segment (default: eth0 /24)
set -u

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

exe="${1:-${ORBYN_EXE:-}}"
if [ -z "$exe" ]; then
  for cand in \
    "$repo_root"/target/*/release/orbyn.exe \
    "$repo_root"/target/release/orbyn.exe; do
    [ -f "$cand" ] && exe="$cand" && break
  done
fi
[ -n "$exe" ] && [ -f "$exe" ] || {
  echo "no orbyn.exe found; build it first, e.g." >&2
  echo "  cargo build --release --target x86_64-pc-windows-gnu" >&2
  exit 2
}
exe="$(cd "$(dirname "$exe")" && pwd)/$(basename "$exe")"

if [ -z "${ORBYN_WINE+x}" ]; then
  if command -v wine >/dev/null 2>&1; then ORBYN_WINE=wine; else ORBYN_WINE=; fi
fi
if [ -n "$ORBYN_WINE" ]; then
  export WINEDEBUG=-all
  RUN=("$ORBYN_WINE" "$exe")
else
  RUN=("$exe")
fi

work="$(mktemp -d)"
listener_pid=""
cleanup() {
  [ -n "$listener_pid" ] && kill "$listener_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT
cd "$work"

pass=0
fail=0
skip=0

run() {
  out="$("${RUN[@]}" "$@" 2>&1)"
  st=$?
}
has() { printf '%s' "$out" | grep -qF -- "$1"; }

ok() {
  pass=$((pass + 1))
  printf 'ok   %s\n' "$1"
}
bad() {
  fail=$((fail + 1))
  printf 'FAIL %s\n' "$1"
  printf '  cmd:    %s\n' "$2"
  printf '  want:   %s\n' "$3"
  printf '  status: %s\n' "$st"
  printf '  output: %s\n' "$(printf '%s' "$out" | head -c 400)"
}
skip_check() {
  skip=$((skip + 1))
  printf 'skip %s (%s)\n' "$1" "$2"
}

expect_contains() {
  local name="$1" want="$2"; shift 2
  run "$@"
  if [ "$st" -eq 0 ] && has "$want"; then ok "$name"; else bad "$name" "$*" "exit 0 and '$want'"; fi
}
expect_fails() {
  local name="$1" want="$2"; shift 2
  run "$@"
  if [ "$st" -ne 0 ] && has "$want"; then ok "$name"; else bad "$name" "$*" "non-zero exit and '$want'"; fi
}

# --- pick a free top-swept TCP port and listen on 0.0.0.0 there ------------
port=""
for p in 6379 5432 3306 9200 27017 11211 9000; do
  if python3 -c "import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',$p));s.close()" 2>/dev/null; then
    port="$p"
    break
  fi
done
[ -n "$port" ] || { echo "no free TCP port among the swept top ports" >&2; exit 2; }

cat > listener.py <<'PY'
import socket, sys, threading

port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port))
srv.listen(128)


def handle(conn):
    try:
        conn.sendall(b"ORBYN-SCAN-TARGET\r\n")
    except OSError:
        pass
    finally:
        conn.close()


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PY

python3 listener.py "$port" >/dev/null 2>&1 &
listener_pid=$!
sleep 1
if ! kill -0 "$listener_pid" 2>/dev/null; then
  echo "failed to start the scan listener on port $port" >&2
  exit 2
fi
printf 'listening on 0.0.0.0:%s\n\n' "$port"

# Fast, deterministic sweep: no ICMP liveness, no UDP, no reverse DNS.
export ORBYN_NATIVE_LIVENESS=0
export ORBYN_NATIVE_UDP=0
export ORBYN_NATIVE_REVERSE_DNS=0
export ORBYN_NATIVE_CONNECT_TIMEOUT_MS=300

# --- S1: single-host real scan --------------------------------------------
expect_contains "scan finds a host" "127-0-0-1" \
  --db single.db discover --target 127.0.0.1 --collector native --format csv
expect_contains "scan finds the open service" "tcp,$port" \
  --db single.db services 127.0.0.1 --format csv

# --- S2: multi-host loopback segment --------------------------------------
run --db segment.db discover --target 127.0.0.0/29 --collector native --concurrency 32 --format csv
if [ "$st" -eq 0 ] && has "127-0-0-1" && has "127-0-0-2" && has "127-0-0-3"; then
  ok "segment scan discovers multiple hosts"
else
  bad "segment scan discovers multiple hosts" "discover --target 127.0.0.0/29" \
    "exit 0 with 127-0-0-1/2/3 in the inventory"
fi
expect_contains "segment hosts expose the service" "tcp,$port" \
  --db segment.db services 127.0.0.2 --format csv

# --- S3: real eth0 /24 segment --------------------------------------------
lan_ip="$(ip -4 addr show eth0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -n1)"
[ -n "$lan_ip" ] || lan_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
lan_cidr="${ORBYN_SCAN_CIDR:-${lan_ip%.*}.0/24}"
if [ -n "$lan_ip" ]; then
  lan_id="${lan_ip//./-}"
  # The /24 is mostly silent hosts, so the sweep is slower than loopback.
  run --db lan.db discover --target "$lan_cidr" --collector native --concurrency 64 --format csv
  if [ "$st" -eq 0 ] && has "$lan_id"; then
    ok "lan segment scan discovers this host ($lan_ip)"
  else
    bad "lan segment scan discovers this host ($lan_ip)" \
      "discover --target $lan_cidr" "exit 0 with $lan_id in the inventory"
  fi
  found_others="$(printf '%s' "$out" | grep -c '^[0-9]\{1,3\}-[0-9]\{1,3\}-[0-9]\{1,3\}-[0-9]\{1,3\},' || true)"
  printf 'info %s: %s assets discovered across %s\n' "lan scan" "$found_others" "$lan_cidr"
  expect_contains "lan host exposes the service" "tcp,$port" \
    --db lan.db services "$lan_ip" --format csv
else
  skip_check "lan segment scan" "no eth0 address detected"
fi

# --- S4: auto selects native and says so ----------------------------------
expect_contains "auto selects native" "auto: native collector selected" \
  --db auto.db discover --target 127.0.0.1 --collector auto

# --- S5: the sweep is recorded as a job -----------------------------------
run --db segment.db jobs --format csv
if [ "$st" -eq 0 ] && has "native,succeeded"; then
  ok "discovery job recorded"
else
  bad "discovery job recorded" "jobs --format csv" "'native,succeeded' row"
fi

# --- S6: re-scan reconciles instead of duplicating ------------------------
expect_contains "re-scan succeeds" "127-0-0-1" \
  --db single.db discover --target 127.0.0.1 --collector native --format csv
run --db single.db assets --format csv
rows="$(printf '%s' "$out" | grep -c '^127-0-0-1,' || true)"
if [ "$st" -eq 0 ] && [ "$rows" -eq 1 ]; then
  ok "re-scan reconciles the host"
else
  bad "re-scan reconciles the host" "assets --format csv" "exactly one 127-0-0-1 row (got $rows)"
fi

# --- S7: oversized scope is refused ---------------------------------------
expect_fails "oversized scope refused" "exceeds the maximum allowed scope" \
  --db scope.db discover --target 0.0.0.0/0 --collector native

printf '\n%s passed, %s failed, %s skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
