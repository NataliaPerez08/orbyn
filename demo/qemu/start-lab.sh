#!/usr/bin/env bash
# Set up the lab network and boot the 4 VMs.
# Needs sudo once per host for the bridge and NAT rule; QEMU itself runs
# unprivileged via the setuid qemu-bridge-helper.
set -euo pipefail
cd "$(dirname "$0")"

BRIDGE=br0
LAB_NET=192.0.2.0/24
HOST_IP=192.0.2.1/24

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need qemu-system-x86_64
need ssh
need ip

for name in web-01 api-01 db-01 legacy-01; do
  if [ ! -f "disks/$name.qcow2" ] || [ ! -f "seeds/$name.iso" ]; then
    echo "missing disks/seeds for $name — run ./create-vms.sh first" >&2
    exit 1
  fi
done

# --- network setup (idempotent) ---
if ! ip link show "$BRIDGE" &>/dev/null; then
  echo "creating bridge $BRIDGE with host IP $HOST_IP (sudo)"
  sudo ip link add "$BRIDGE" type bridge
  sudo ip addr add "$HOST_IP" dev "$BRIDGE"
  sudo ip link set "$BRIDGE" up
fi
if [ ! -f /etc/qemu/bridge.conf ] || ! grep -qw "$BRIDGE" /etc/qemu/bridge.conf; then
  echo "allowing $BRIDGE in /etc/qemu/bridge.conf (sudo)"
  sudo mkdir -p /etc/qemu
  echo "allow $BRIDGE" | sudo tee -a /etc/qemu/bridge.conf >/dev/null
fi
# NAT so the VMs can reach package mirrors through the host.
WAN=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! sudo iptables -t nat -C POSTROUTING -s "$LAB_NET" -o "$WAN" -j MASQUERADE 2>/dev/null; then
  sudo iptables -t nat -A POSTROUTING -s "$LAB_NET" -o "$WAN" -j MASQUERADE
fi

# --- launch ---
if [ -w /dev/kvm ]; then
  ACCEL=kvm
else
  ACCEL=tcg
  echo "WARNING: /dev/kvm not writable — using TCG emulation, boot will be slow" >&2
fi
mkdir -p logs

launch() { # name mac memory_mib vcpus
  local name=$1 mac=$2 mem=$3 cpus=$4
  if [ -f "$name.pid" ] && kill -0 "$(cat "$name.pid")" 2>/dev/null; then
    echo "$name already running (pid $(cat "$name.pid"))"
    return
  fi
  echo "starting $name"
  qemu-system-x86_64 \
    -machine accel="$ACCEL" \
    -m "$mem" -smp "$cpus" \
    -drive file="disks/$name.qcow2",if=virtio,format=qcow2 \
    -drive file="seeds/$name.iso",if=virtio,format=raw,readonly=on \
    -netdev bridge,br="$BRIDGE",id=net0 \
    -device virtio-net-pci,netdev=net0,mac="$mac" \
    -display none \
    -serial "file:logs/$name.console.log" \
    -daemonize -pidfile "$name.pid"
}

launch web-01 52:54:00:00:00:11 2048 2
launch api-01 52:54:00:00:00:12 2048 2
launch db-01 52:54:00:00:00:13 2048 2
launch legacy-01 52:54:00:00:00:14 1024 1

# --- wait until cloud-init finished on every VM (packages install there) ---
wait_ready() { # ip
  local ip=$1
  for _ in $(seq 1 90); do
    if ssh -i lab_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=5 "deploy@$ip" \
      'for i in $(seq 1 60); do [ -e /var/lib/cloud/instance/boot-finished ] && exit 0; sleep 2; done; exit 1' \
      2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}

for spec in "web-01 192.0.2.11" "api-01 192.0.2.12" "db-01 192.0.2.13" "legacy-01 192.0.2.14"; do
  read -r name ip <<<"$spec"
  echo -n "waiting for $name ($ip) to finish cloud-init... "
  if wait_ready "$ip"; then
    echo ok
  else
    echo "TIMEOUT — inspect logs/$name.console.log" >&2
    exit 1
  fi
done

echo
echo "lab is up. run ./discover.sh to collect the estate into orbyn"
