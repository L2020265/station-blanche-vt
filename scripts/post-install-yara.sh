#!/usr/bin/env bash
# Post-installation : télécharge les règles YARA (simple)

set -euo pipefail

BASE="${1:-/srv/station-blanche}"

echo "📥 Téléchargement des règles YARA depuis GitHub..."
python3 "$BASE/scripts/download_yara_simple.py" 2>&1 || {
    echo "⚠️  Avertissement: Le téléchargement a échoué"
    echo "Continuez sans règles GitHub (règles locales seulement)"
}

echo ""
echo "✅ Installation terminée!"
echo "Les règles YARA seront scannées directement via yara -r"


