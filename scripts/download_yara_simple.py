#!/usr/bin/env python3
"""
Télécharge UNIQUEMENT les règles YARA depuis GitHub (simple et efficace)
Pas d'index.yar, pas de déduplications complexes
"""
import subprocess
from pathlib import Path

def download_yara_rules():
    """Télécharge les règles YARA du GitHub"""
    rules_dir = Path(__file__).parent.parent / "rules"
    malware_dir = rules_dir / "malware"
    
    print("📥 Téléchargement des règles YARA depuis GitHub...")
    print("─" * 70)
    
    # Si le dossier existe déjà, mettre à jour
    if (malware_dir / ".git").exists():
        print("Mise à jour du repo existant...")
        result = subprocess.run(
            ["git", "-C", str(malware_dir), "pull", "--quiet"],
            capture_output=True,
            text=True,
            timeout=120
        )
    else:
        # Créer le dossier et cloner
        malware_dir.mkdir(parents=True, exist_ok=True)
        print("Clonage du repo...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", 
             "https://github.com/Yara-Rules/rules.git", 
             str(malware_dir)],
            capture_output=True,
            text=True,
            timeout=300
        )
    
    if result.returncode == 0:
        # Compter les fichiers téléchargés
        yara_files = list(malware_dir.rglob("*.yar")) + list(malware_dir.rglob("*.yara"))
        print(f"✓ Succès! {len(yara_files)} fichiers YARA trouvés")
        print(f"  Dossier: {malware_dir}")
        return True
    else:
        print(f"✗ Erreur: {result.stderr}")
        return False

if __name__ == "__main__":
    success = download_yara_rules()
    exit(0 if success else 1)
