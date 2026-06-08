#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-}"
DST="/srv/station-blanche/rules"
if [[ -z "$SRC" || ! -d "$SRC" ]]; then
  echo "Usage: $0 /chemin/yara-rules" >&2
  exit 1
fi
if [[ -f "$SRC/SHA256SUMS" ]]; then
  (cd "$SRC" && sha256sum -c SHA256SUMS)
fi
rsync -a --delete "$SRC/" "$DST/"
chown -R root:stationblanche "$DST"
chmod -R u=rwX,g=rX,o= "$DST"
echo "Règles YARA importées."
