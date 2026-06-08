#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-}"
if [[ -z "$SRC" || ! -d "$SRC" ]]; then
  echo "Usage: $0 /chemin/clamav-db" >&2
  exit 1
fi
if [[ -f "$SRC/SHA256SUMS" ]]; then
  (cd "$SRC" && sha256sum -c SHA256SUMS)
fi
install -d -o clamav -g clamav -m 0755 /var/lib/clamav
cp "$SRC"/*.cvd "$SRC"/*.cld /var/lib/clamav/ 2>/dev/null || true
chown clamav:clamav /var/lib/clamav/*
systemctl restart clamav-daemon || true
echo "Bases ClamAV importées."
