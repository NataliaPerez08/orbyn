#!/usr/bin/env bash
# Create the demo lab VMs: SSH key, qcow2 overlays, cloud-init seed ISOs.
# Prereqs: ./download-images.sh; qemu-img; cloud-localds (cloud-image-utils)
# or genisoimage.
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need qemu-img
need ssh-keygen
need sed

# name ip mac image memory_mib vcpus
VMS=(
  "web-01 192.0.2.11 52:54:00:00:00:11 noble-server-cloudimg-amd64.img 2048 2"
  "api-01 192.0.2.12 52:54:00:00:00:12 jammy-server-cloudimg-amd64.img 2048 2"
  "db-01 192.0.2.13 52:54:00:00:00:13 focal-server-cloudimg-amd64.img 2048 2"
  "legacy-01 192.0.2.14 52:54:00:00:00:14 debian-11-generic-amd64.qcow2 1024 1"
)

if [ ! -f lab_key ]; then
  ssh-keygen -t ed25519 -N "" -f lab_key -C orbyn-demo-lab >/dev/null
  echo "generated SSH key: lab_key / lab_key.pub"
fi
PUBKEY=$(cat lab_key.pub)

mkdir -p disks seeds

make_seed() { # name — builds seeds/<name>.iso from seeds/<name>/{user-data,meta-data,network-config}
  local name=$1 dir="seeds/$1"
  if command -v cloud-localds >/dev/null; then
    cloud-localds --network-config "$dir/network-config" "seeds/$name.iso" "$dir/user-data" "$dir/meta-data"
  elif command -v genisoimage >/dev/null; then
    genisoimage -quiet -output "seeds/$name.iso" -volid cidata -joliet -rock \
      "$dir/user-data" "$dir/meta-data" "$dir/network-config"
  else
    echo "need cloud-localds (package cloud-image-utils) or genisoimage" >&2
    exit 1
  fi
}

for spec in "${VMS[@]}"; do
  read -r name ip mac image mem cpus <<<"$spec"
  if [ ! -f "images/$image" ]; then
    echo "missing images/$image — run ./download-images.sh first" >&2
    exit 1
  fi

  echo "creating $name ($ip)"
  rm -f "disks/$name.qcow2"
  qemu-img create -f qcow2 -F qcow2 -b "$PWD/images/$image" "disks/$name.qcow2" 20G >/dev/null

  dir="seeds/$name"
  mkdir -p "$dir"
  sed "s|__LAB_KEY__|$PUBKEY|" "cloud-init/${name}-user-data.yaml" > "$dir/user-data"
  cat > "$dir/meta-data" <<EOF
instance-id: $name
local-hostname: $name
EOF
  cat > "$dir/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match:
      mac-address: "$mac"
    set-name: eth0
    addresses:
      - $ip/24
    routes:
      - to: default
        via: 192.0.2.1
    nameservers:
      addresses: [9.9.9.9, 1.1.1.1]
EOF
  make_seed "$name"
done

echo "done. boot the lab with ./start-lab.sh"
