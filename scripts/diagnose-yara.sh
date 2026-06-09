#!/usr/bin/env bash
# Script de diagnostic pour vérifier les règles YARA en production
# Usage: bash scripts/diagnose-yara.sh [path_to_test_file]

BASE="${1:-.}"
RULES_INDEX="$BASE/rules/index.yar"
TEST_FILE="${2:-/tmp/eicar.com}"

echo "🔍 DIAGNOSTIC YARA EN PRODUCTION"
echo "═════════════════════════════════════════════════════"

echo ""
echo "📋 État des règles YARA"
echo "─────────────────────────────────────────────────────"

# Vérifier l'index
if [[ -f "$RULES_INDEX" ]]; then
    echo "✓ Index YARA: $RULES_INDEX"
    echo "  Lignes: $(wc -l < "$RULES_INDEX")"
    echo "  Fichiers inclus:"
    grep '^include' "$RULES_INDEX" | head -20
    echo ""
else
    echo "❌ Index YARA manquant: $RULES_INDEX"
fi

# Compter les fichiers YARA
echo ""
echo "📊 Statistiques"
echo "─────────────────────────────────────────────────────"
YARA_COUNT=$(find "$BASE/rules" -name "*.yar" -o -name "*.yara" | grep -v index.yar | wc -l)
echo "Fichiers YARA trouvés: $YARA_COUNT"

# Chercher les règles EICAR
echo ""
echo "🎯 Recherche de la règle EICAR"
echo "─────────────────────────────────────────────────────"
if grep -r "MALW_Eicar\|Eicar" "$BASE/rules" 2>/dev/null | head -5; then
    echo "✓ Règle EICAR trouvée"
else
    echo "❌ Règle EICAR non trouvée"
fi

# Tester avec YARA
echo ""
echo "🧪 Test YARA"
echo "─────────────────────────────────────────────────────"

# Créer un fichier EICAR si absent
if [[ ! -f "$TEST_FILE" ]]; then
    echo "Création d'un fichier EICAR de test..."
    echo -n 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_FILE"
fi

echo "Fichier de test: $TEST_FILE"
echo ""

# Vérifier la syntaxe de l'index
echo "Vérification de la syntaxe YARA..."
if yara --print-strings "$RULES_INDEX" "$TEST_FILE" 2>&1 | head -20; then
    echo ""
    echo "✓ Index YARA valide"
else
    echo "❌ Erreur YARA"
fi

echo ""
echo "═════════════════════════════════════════════════════"
echo ""
echo "Actions possibles :"
echo "1. Télécharger/mettre à jour les règles :"
echo "   python3 scripts/download_yara_rules.py"
echo "   python3 scripts/generate_safe_yara_index.py"
echo ""
echo "2. Vérifier l'intégrité du fichier EICAR :"
echo "   file $TEST_FILE"
echo ""
