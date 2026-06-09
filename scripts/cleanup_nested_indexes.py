#!/usr/bin/env python3
"""
Nettoie les index.yar dans les sous-dossiers (malware/, webshells/, etc)
pour éviter les conflits avec l'index principal
"""
from pathlib import Path

def cleanup_nested_indexes(rules_dir):
    """Supprime les index.yar dans les sous-dossiers"""
    rules_dir = Path(rules_dir)
    
    print("🗑️  Nettoyage des index.yar imbriqués")
    print("─" * 70)
    
    removed_count = 0
    
    # Trouver tous les index.yar SAUF celui à la racine
    for index_file in rules_dir.rglob("index.yar"):
        # Garder seulement l'index à la racine de rules/
        if index_file.parent == rules_dir:
            print(f"✓ Index principal: {index_file.relative_to(rules_dir)}")
            continue
        
        # Supprimer les autres
        try:
            index_file.unlink()
            print(f"✓ Supprimé: {index_file.relative_to(rules_dir)}")
            removed_count += 1
        except Exception as e:
            print(f"✗ Erreur: {index_file.relative_to(rules_dir)}: {e}")
    
    return removed_count

if __name__ == "__main__":
    rules_dir = Path(__file__).parent.parent / "rules"
    
    if not rules_dir.exists():
        print("❌ Le dossier 'rules' n'existe pas")
        exit(1)
    
    removed = cleanup_nested_indexes(rules_dir)
    print(f"\n✓ {removed} index(es) imbriqué(es) supprimé(es)")
