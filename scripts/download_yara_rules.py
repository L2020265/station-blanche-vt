#!/usr/bin/env python3
"""
Script pour télécharger et gérer les règles YARA depuis GitHub
"""
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_CONFIG = RULES_DIR / "rules_config.json"

# Configuration des sources YARA
YARA_SOURCES = {
    "malware": {
        "url": "https://github.com/Yara-Rules/rules.git",
        "path": "malware",
        "enabled": True
    },
    "webshells": {
        "url": "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
        "path": "webshells",
        "enabled": True
    },
    "community": {
        "url": "https://github.com/0xe4/malware_hunting.git",
        "path": ".",
        "enabled": False
    }
}

def create_config():
    """Crée le fichier de configuration"""
    config = {
        "sources": YARA_SOURCES,
        "last_updated": datetime.now().isoformat(),
        "rules_count": 0
    }
    os.makedirs(RULES_DIR, exist_ok=True)
    with open(RULES_CONFIG, "w") as f:
        json.dump(config, f, indent=2)
    print(f"✓ Fichier config créé: {RULES_CONFIG}")

def download_rules(source_name, source_info):
    """Télécharge les règles YARA d'une source"""
    if not source_info["enabled"]:
        print(f"⊘ {source_name} désactivé")
        return
    
    source_dir = RULES_DIR / source_name
    os.makedirs(source_dir, exist_ok=True)
    
    print(f"📥 Téléchargement {source_name}...")
    
    # Vérifier si le repo existe déjà
    is_existing = (source_dir / ".git").exists()
    
    # Si le dossier existe, mettre à jour; sinon, cloner
    if is_existing:
        print(f"   Mise à jour (repo existant)...")
        result = subprocess.run(
            ["git", "-C", str(source_dir), "pull", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60
        )
    else:
        print(f"   Clonage du repo...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", source_info["url"], str(source_dir)],
            capture_output=True,
            text=True,
            timeout=120
        )
    
    if result.returncode == 0:
        rules_count = count_yara_files(source_dir)
        print(f"✓ {source_name}: {rules_count} fichiers trouvés")
        return rules_count
    else:
        print(f"✗ Erreur: {result.stderr}")
        return 0

def count_yara_files(directory):
    """Compte les fichiers .yar et .yara"""
    count = 0
    for ext in ["*.yar", "*.yara"]:
        count += len(list(Path(directory).rglob(ext)))
    return count

def list_available_rules():
    """Liste les règles disponibles"""
    print("\n📋 Règles YARA disponibles:")
    for source_name in YARA_SOURCES:
        source_dir = RULES_DIR / source_name
        if source_dir.exists():
            count = count_yara_files(source_dir)
            print(f"  • {source_name}: {count} fichiers")

def main():
    """Fonction principale"""
    print("🔍 Gestionnaire des règles YARA\n")
    
    # Créer ou mettre à jour la config
    if not RULES_CONFIG.exists():
        create_config()
    
    # Télécharger les règles
    total_rules = 0
    for source_name, source_info in YARA_SOURCES.items():
        count = download_rules(source_name, source_info)
        total_rules += count
    
    # Lister les règles disponibles
    list_available_rules()
    print(f"\n✅ Total: {total_rules} règles YARA chargées")

if __name__ == "__main__":
    main()