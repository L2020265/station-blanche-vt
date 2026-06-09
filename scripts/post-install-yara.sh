#!/usr/bin/env bash
# Post-installation : télécharge les règles YARA (simple)

set -euo pipefail

BASE="${1:-/srv/station-blanche}"

echo "📥 Téléchargement des règles YARA depuis GitHub..."
python3 "$BASE/scripts/download_yara_simple.py"

echo ""
echo "✅ Installation terminée!"
echo "Les règles YARA du GitHub seront utilisées directement (récursif)"

