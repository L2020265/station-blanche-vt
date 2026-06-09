#!/usr/bin/env python3
"""
Script pour générer un index YARA à partir des règles téléchargées
"""
import os
from pathlib import Path

def generate_yara_index():
    """Génère un fichier index.yar qui inclut toutes les règles disponibles"""
    
    rules_dir = Path(__file__).parent.parent / "rules"
    os.makedirs(rules_dir, exist_ok=True)
    
    index_file = rules_dir / "index.yar"
    
    # Trouver tous les fichiers .yar et .yara
    yara_files = []
    for ext in ["*.yar", "*.yara"]:
        yara_files.extend(sorted(rules_dir.rglob(ext)))
    
    # Exclure index.yar lui-même
    yara_files = [f for f in yara_files if f.name != "index.yar"]
    
    print(f"📝 Création de index.yar avec {len(yara_files)} fichiers")
    
    # Générer l'index avec les includes
    with open(index_file, "w", encoding="utf-8") as f:
        f.write("// Index YARA auto-généré - Ne pas modifier\n")
        f.write(f"// Dernière mise à jour: {Path.cwd()}\n")
        f.write(f"// Total: {len(yara_files)} fichiers\n\n")
        
        for yara_file in yara_files:
            # Utiliser des chemins relatifs
            relative_path = yara_file.relative_to(rules_dir)
            f.write(f'include "{relative_path}"\n')
    
    print(f"✓ Index créé: {index_file}")
    return index_file

if __name__ == "__main__":
    generate_yara_index()
