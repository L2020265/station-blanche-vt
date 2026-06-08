#!/usr/bin/env bash
set -euo pipefail
MNT="${1:-/mnt/incoming}"
umount "$MNT"
echo "Démonté : $MNT"
