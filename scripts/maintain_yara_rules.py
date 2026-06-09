#!/usr/bin/env python3
"""
Script complet d'installation et de maintenance des règles YARA
- Télécharge les règles depuis GitHub
- Déduplique les fichiers
- Génère l'index YARA
"""
import sys
import subprocess
from pathlib import Path

def run_script(script_name, args=[]):
    """Exécute un script Python"""
    script_path = Path(__file__).parent / script_name
    cmd = [sys.executable, str(script_path)] + args
    print(f"\n▶️  Exécution: {script_name} {' '.join(args)}")
    print("─" * 70)
    result = subprocess.run(cmd)
    return result.returncode == 0

def main():
    print("=" * 70)
    print("🔧 MAINTENANCE DES RÈGLES YARA")
    print("=" * 70)
    
    scripts = [
        ("download_yara_rules.py", [], "Téléchargement des règles depuis GitHub"),
        ("cleanup_nested_indexes.py", [], "Suppression des index.yar imbriqués"),
        ("deduplicate_yara.py", ["clean"], "Suppression des fichiers dupliqués"),
        ("generate_safe_yara_index.py", [], "Génération sécurisée de l'index YARA (gère les doublons)"),
    ]
    
    failed = []
    
    for script, args, description in scripts:
        print(f"\n📦 Étape: {description}")
        if not run_script(script, args):
            print(f"✗ Erreur lors de {script}")
            failed.append(script)
        else:
            print(f"✓ {description} - OK")
    
    print("\n" + "=" * 70)
    
    if failed:
        print(f"❌ {len(failed)} étape(s) échouée(s):")
        for script in failed:
            print(f"  • {script}")
        sys.exit(1)
    else:
        print("✅ MAINTENANCE COMPLÈTE - SUCCÈS")
        print("Vos règles YARA sont à jour et prêtes à l'emploi!")
        sys.exit(0)

if __name__ == "__main__":
    main()
