#!/usr/bin/env bash
# Download the cloud images for the QEMU demo lab and verify their checksums.
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl
need sha256sum
need sha512sum

mkdir -p images

# base-url | image file | checksum file | checksum tool
SPECS=(
  "https://cloud-images.ubuntu.com/noble/current noble-server-cloudimg-amd64.img SHA256SUMS sha256sum"
  "https://cloud-images.ubuntu.com/jammy/current jammy-server-cloudimg-amd64.img SHA256SUMS sha256sum"
  "https://cloud-images.ubuntu.com/focal/current focal-server-cloudimg-amd64.img SHA256SUMS sha256sum"
  "https://cloud.debian.org/images/cloud/bullseye/latest debian-11-generic-amd64.qcow2 SHA512SUMS sha512sum"
)

for spec in "${SPECS[@]}"; do
  read -r base file sums tool <<<"$spec"
  if [ -s "images/$file" ]; then
    echo "images/$file already present, skipping download"
  else
    echo "downloading $file"
    curl -fSL --retry 3 -o "images/$file" "$base/$file"
  fi
  curl -fsSL "$base/$sums" | grep -E "[ *]$file\$" > "images/$file.checksum"
  if (cd images && "$tool" -c "$file.checksum"); then
    echo "images/$file verified"
  else
    echo "checksum FAILED for images/$file — delete it and re-run" >&2
    exit 1
  fi
done

echo "done. create the VMs with ./create-vms.sh"
