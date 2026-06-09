#!/usr/bin/env python3
"""
Déduplique les règles YARA en supprimant les fichiers en doublon
"""
import hashlib
from pathlib import Path
from collections import defaultdict

def get_file_hash(file_path):
    """Calcule le hash SHA256 d'un fichier"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"⚠️  Erreur de hash {file_path}: {e}")
        return None

def find_duplicate_files(rules_dir):
    """Trouve les fichiers YARA dupliqués par contenu"""
    hash_to_files = defaultdict(list)
    
    # Calculer le hash de chaque fichier YARA
    for yara_file in sorted(rules_dir.rglob("*")):
        if yara_file.name in ["index.yar", "README.md"]:
            continue
        if yara_file.suffix in [".yar", ".yara"]:
            file_hash = get_file_hash(yara_file)
            if file_hash:
                hash_to_files[file_hash].append(yara_file)
    
    # Identifier les doublons
    duplicates = {h: files for h, files in hash_to_files.items() 
                  if len(files) > 1}
    
    return hash_to_files, duplicates

def remove_duplicate_files(rules_dir, dry_run=True):
    """Supprime les fichiers YARA dupliqués"""
    hash_to_files, duplicates = find_duplicate_files(rules_dir)
    
    if not duplicates:
        print("✓ Pas de fichiers en doublon trouvés!")
        return 0
    
    print(f"🔍 {len(duplicates)} groupe(s) de fichiers dupliqués détectés:\n")
    
    total_removed = 0
    
    for file_hash, files in duplicates.items():
        print(f"  Group (hash: {file_hash[:8]}...):")
        for i, file_path in enumerate(files):
            rel_path = file_path.relative_to(rules_dir)
            size = file_path.stat().st_size
            print(f"      {i+1}. {rel_path} ({size} bytes)")
        
        # Garder le premier fichier (généralement la meilleure source)
        # Supprimer les autres
        to_delete = files[1:]
        
        print(f"     → Garder: {files[0].relative_to(rules_dir)}")
        print(f"     → Supprimer: {len(to_delete)} fichier(s)")
        
        for file_to_delete in to_delete:
            try:
                if not dry_run:
                    file_to_delete.unlink()
                    total_removed += 1
                    print(f"        ✓ Supprimé: {file_to_delete.relative_to(rules_dir)}")
                else:
                    print(f"        [DRY RUN] Supprimerait: {file_to_delete.relative_to(rules_dir)}")
                    total_removed += 1
            except Exception as e:
                print(f"        ✗ Erreur: {e}")
        print()
    
    return total_removed

def report_duplicates(rules_dir):
    """Génère un rapport sur les fichiers dupliqués"""
    hash_to_files, duplicates = find_duplicate_files(rules_dir)
    
    print("=" * 70)
    print("📊 RAPPORT DE DÉDUPLICATION YARA")
    print("=" * 70)
    
    yara_files = [f for f in rules_dir.rglob("*") 
                  if f.suffix in [".yar", ".yara"] and f.name != "index.yar"]
    
    total_size = sum(f.stat().st_size for f in yara_files)
    duplicate_size = sum(f.stat().st_size for files in duplicates.values() 
                        for f in files[1:])
    
    print(f"\nFichiers YARA: {len(yara_files)}")
    print(f"Taille totale: {total_size / (1024*1024):.2f} MB")
    print(f"Fichiers dupliqués: {len(duplicates)}")
    print(f"Occurrences redondantes: {sum(len(files)-1 for files in duplicates.values())}")
    print(f"Espace à économiser: {duplicate_size / (1024*1024):.2f} MB")
    
    if duplicates:
        print("\n⚠️  FICHIERS EN DOUBLON:")
        for file_hash, files in sorted(duplicates.items()):
            print(f"\n  Hash {file_hash[:16]}...:")
            for file_path in files:
                size = file_path.stat().st_size
                print(f"    • {file_path.relative_to(rules_dir)} ({size} bytes)")
    else:
        print("\n✓ Aucun fichier en doublon trouvé")
    
    print("\n" + "=" * 70)

def main():
    rules_dir = Path(__file__).parent.parent / "rules"
    
    if not rules_dir.exists():
        print("❌ Le dossier 'rules' n'existe pas")
        return
    
    import sys
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "report":
            report_duplicates(rules_dir)
        elif cmd == "dry-run":
            print("🔍 Mode simulation (aucun fichier ne sera supprimé):\n")
            removed = remove_duplicate_files(rules_dir, dry_run=True)
            print(f"\n📊 Résultat: {removed} fichier(s) seraient supprimés")
        elif cmd == "clean":
            print("🗑️  Suppression des fichiers dupliqués:\n")
            removed = remove_duplicate_files(rules_dir, dry_run=False)
            print(f"\n✓ {removed} fichier(s) supprimé(s)")
        else:
            print("Usage:")
            print("  python deduplicate_yara.py report   - Voir le rapport")
            print("  python deduplicate_yara.py dry-run  - Simulation de suppression")
            print("  python deduplicate_yara.py clean    - Supprimer les doublons")
    else:
        print("Usage:")
        print("  python deduplicate_yara.py report   - Voir le rapport")
        print("  python deduplicate_yara.py dry-run  - Simulation de suppression")
        print("  python deduplicate_yara.py clean    - Supprimer les doublons")
        report_duplicates(rules_dir)

if __name__ == "__main__":
    main()
