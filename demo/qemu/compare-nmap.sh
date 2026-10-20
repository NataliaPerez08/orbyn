#!/usr/bin/env bash
# NMAP-010 — record a native-vs-nmap comparison against the running lab.
#
# This is the parity evidence that gates the `auto` collector mode and
# any default flip (ADR-0002 D5; NMAP_REPLACEMENT_PLAN §7). Both
# collectors run through the same orbyn normalization, then the script
# diffs hosts, TCP ports, service names and wall-clock runtime against
# the lab's known ground truth (the cloud-init user-data):
#
#   web-01     192.0.2.11  22, 80          (nginx)
#   api-01     192.0.2.12  22, 8080        (flask)
#   db-01      192.0.2.13  22, 5432, 6379  (postgres, redis)
#   legacy-01  192.0.2.14  22
#
# Requires: the lab up (./start-lab.sh), nmap on PATH (the nmap
# collector shells out to it) and an orbyn binary (ORBYN_BIN=... to
# point at one). Unprivileged runs get nmap's connect scan — the same
# posture as the native collector, so the comparison is fair.
#
# Output: results/<stamp>/ with both databases, the CSV extracts and a
# markdown report; the report path is printed at the end. Never scan
# anything but the isolated 192.0.2.0/24 lab bridge.
set -euo pipefail
cd "$(dirname "$0")"

ORBYN="${ORBYN_BIN:-orbyn}"
command -v "$ORBYN" >/dev/null || { echo "orbyn not found (set ORBYN_BIN=/path/to/orbyn)" >&2; exit 1; }
command -v nmap >/dev/null || { echo "nmap not found (the nmap collector needs it)" >&2; exit 1; }

NET=192.0.2.0/24
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="results/nmap-vs-native-$STAMP"
mkdir -p "$OUT"

# Ground truth: "ip name tcp-port..."
TRUTH=(
  "192.0.2.11 web-01 22 80"
  "192.0.2.12 api-01 22 8080"
  "192.0.2.13 db-01 22 5432 6379"
  "192.0.2.14 legacy-01 22"
)

# --- run one collector pass and extract normalized CSVs ---------------
scan() { # collector label -> echoes runtime seconds
  local collector=$1 label=$2
  local db="$OUT/$collector.db" t0 t1
  echo "== $label: orbyn discover --collector $collector --target $NET ==" >&2
  t0=$(date +%s)
  "$ORBYN" --db "$db" discover --target "$NET" --collector "$collector" >&2
  t1=$(date +%s)
  "$ORBYN" --db "$db" assets --format csv > "$OUT/$collector-assets.csv"
  : > "$OUT/$collector-services.csv"
  for row in "${TRUTH[@]}"; do
    local ip
    ip=$(awk '{print $1}' <<<"$row")
    if "$ORBYN" --db "$db" services "$ip" --format csv > "$OUT/$collector-services-$ip.csv" 2>/dev/null; then
      tail -n +2 "$OUT/$collector-services-$ip.csv" >> "$OUT/$collector-services.csv"
    fi
  done
  echo $((t1 - t0))
}

NMAP_SECS=$(scan nmap "nmap adapter")
NATIVE_SECS=$(scan native "native adapter")

# --- per-collector metrics --------------------------------------------
hosts_found() { # assets csv -> sorted unique ips
  tail -n +2 "$1" | awk -F, '{print $2}' | sort -u
}

open_tcp_ports() { # services csv ip -> sorted ports (state open)
  awk -F, -v ip="$2" '$1 ~ ("^" ip "$") && $2 == "tcp" && $5 == "open" {print $3}' "$1" | sort -n -u
}

named_tcp_ports() { # services csv ip -> ports with a non-empty name
  awk -F, -v ip="$2" '$1 ~ ("^" ip "$") && $2 == "tcp" && $5 == "open" && $4 != "" {print $3}' "$1" | sort -n -u
}

udp_open_ports() { # services csv -> "ip:port" rows (native-only capability)
  awk -F, '$2 == "udp" && ($5 == "open" || $5 == "open|filtered") {print $1 ":" $3}' "$1" | sort -u
}

PASS=0; FAIL=0
check() { # description ok?
  if [ "$2" = 1 ]; then PASS=$((PASS + 1)); echo "  PASS  $1" >&2
  else FAIL=$((FAIL + 1)); echo "  FAIL  $1" >&2; fi
}

report_rows=""
metrics() { # collector label runtime_secs
  local collector=$1 label=$2 runtime=$3
  local assets_csv="$OUT/$collector-assets.csv" services_csv="$OUT/$collector-services.csv"
  local found_ips host_recall="100% (4/4)"
  found_ips=$(hosts_found "$assets_csv")

  # Host recall against the four truth hosts.
  local missing=0
  for row in "${TRUTH[@]}"; do
    local ip; ip=$(awk '{print $1}' <<<"$row")
    grep -qx "$ip" <<<"$found_ips" || { missing=$((missing + 1)); echo "  ($label did not find $ip)" >&2; }
  done
  [ "$missing" -eq 0 ] && check "$label finds all 4 lab hosts" 1 || { check "$label finds all 4 lab hosts" 0; host_recall="$((100 - missing * 25))% ($((4 - missing))/4)"; }

  # Extra hosts beyond the truth (e.g. the bridge gateway) are reported,
  # not penalized — they are legitimate findings.
  local extras
  extras=$(printf '%s\n' "$found_ips" | comm -23 - <(for r in "${TRUTH[@]}"; do awk '{print $1}' <<<"$r"; done | sort -u) | tr '\n' ' ')
  extras="${extras% }"

  # Per-host TCP port recall + service naming.
  local port_line="" name_line=""
  for row in "${TRUTH[@]}"; do
    local ip name; ip=$(awk '{print $1}' <<<"$row"); name=$(awk '{print $2}' <<<"$row")
    local truth_ports found_ports named_ports recall
    truth_ports=$(awk '{for (i=3; i<=NF; i++) print $i}' <<<"$row")
    found_ports=$(open_tcp_ports "$services_csv" "$ip")
    named_ports=$(named_tcp_ports "$services_csv" "$ip")
    recall=$(awk -v found="$found_ports" -v truth="$truth_ports" '
      BEGIN { n = split(truth, t, /\n/); hit = 0;
              for (i = 1; i <= n; i++) if (found ~ ("(^|\n)" t[i] "(\n|$)")) hit++;
              printf "%d/%d", hit, n }')
    port_line+="$name $recall; "
    local named_recall
    named_recall=$(awk -v found="$named_ports" -v truth="$truth_ports" '
      BEGIN { n = split(truth, t, /\n/); hit = 0;
              for (i = 1; i <= n; i++) if (found ~ ("(^|\n)" t[i] "(\n|$)")) hit++;
              printf "%d/%d", hit, n }')
    name_line+="$name $named_recall; "
  done

  local udp_rows
  udp_rows=$(udp_open_ports "$services_csv" | tr '\n' ' ')
  udp_rows="${udp_rows% }"
  report_rows+="| $label | $host_recall | ${port_line%; } | ${name_line%; } | ${runtime}s | ${extras:-none} | ${udp_rows:-none} |
"
  echo "  ($label: runtime ${runtime}s, extra hosts: ${extras:-none}, udp: ${udp_rows:-none})" >&2
}

echo "== comparing against ground truth ==" >&2
metrics nmap "nmap" "$NMAP_SECS"
metrics native "native" "$NATIVE_SECS"

REPORT="$OUT/report.md"
{
  echo "# NMAP-010 — native vs nmap on the QEMU lab"
  echo
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ) · Network: $NET (isolated lab bridge) ·"
  echo "Scope: orbyn discover, default profiles, unprivileged connect scans."
  echo
  echo "| Adapter | Host recall | TCP port recall (per host) | Named ports (per host) | Runtime | Extra hosts | UDP observations |"
  echo "| --- | --- | --- | --- | --- | --- | --- |"
  echo -n "$report_rows"
  echo
  echo "Ground truth (cloud-init): web-01 22,80 · api-01 22,8080 · db-01 22,5432,6379 · legacy-01 22."
  echo "Extra hosts and UDP observations are reported, not penalized: the nmap"
  echo "baseline is TCP-only, and the native UDP sweep is a new capability with"
  echo "conservative \`open|filtered\` states."
  echo
  echo "Checks: $PASS passed, $FAIL failed."
  echo
  echo "Raw data: \`$OUT/{nmap,native}-assets.csv\`, \`$OUT/{nmap,native}-services*.csv\`,"
  echo "and both SQLite databases in the same directory."
} > "$REPORT"

echo
echo "report: $REPORT"
echo "checks: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
