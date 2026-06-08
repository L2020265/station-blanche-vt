#!/usr/bin/env bash
set -euo pipefail

DEV="${1:-}"
MNT="${2:-/mnt/incoming}"

if [[ -z "$DEV" ]]; then
  echo "Usage: $0 /dev/sdX1 [/mnt/incoming]" >&2
  exit 1
fi

mkdir -p "$MNT"
mount -o ro,noexec,nodev,nosuid,sync "$DEV" "$MNT"
echo "Monté en lecture seule sur $MNT"
