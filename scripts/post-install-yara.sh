#!/usr/bin/env bash
# Script post-installation : initialise les règles YARA en production
# À exécuter après install.sh : bash scripts/post-install-yara.sh

set -euo pipefail

BASE="${1:-/srv/station-blanche}"
SCRIPTS_DIR="$BASE/scripts"
RULES_DIR="$BASE/rules"

echo "🔧 Post-installation : Initialisation des règles YARA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Vérifier que les scripts existent
if [[ ! -f "$SCRIPTS_DIR/maintain_yara_rules.py" ]]; then
    echo "❌ Erreur: scripts non trouvés dans $SCRIPTS_DIR"
    exit 1
fi

# Créer le répertoire scripts s'il n'existe pas
mkdir -p "$SCRIPTS_DIR"

echo ""
echo "📥 Étape 1 : Téléchargement des règles YARA depuis GitHub..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPTS_DIR/download_yara_rules.py" || {
    echo "⚠️  Avertissement: Le téléchargement a échoué (connexion réseau?)"
    echo "Les règles locales seront utilisées."
}

echo ""
echo "🗑️  Étape 2 : Suppression des fichiers YARA dupliqués..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPTS_DIR/deduplicate_yara.py" clean || true

echo ""
echo "🔨 Étape 3 : Génération de l'index YARA (gère les doublons)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPTS_DIR/generate_safe_yara_index.py"

echo ""
echo "✅ Post-installation terminée!"
echo ""
echo "Résumé :"
echo "  • Règles YARA téléchargées : $(find "$RULES_DIR" -name '*.yar' -o -name '*.yara' | wc -l) fichiers"
echo "  • Index généré : $RULES_DIR/index.yar"
echo ""
echo "Pour mettre à jour les règles régulièrement, créez une tâche cron :"
echo "  0 2 * * * root python3 $SCRIPTS_DIR/maintain_yara_rules.py >> /var/log/station-blanche/yara-maintenance.log 2>&1"
echo ""
