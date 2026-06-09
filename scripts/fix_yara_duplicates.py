#!/usr/bin/env python3
"""
Détecte et corrige les doublons de règles YARA
"""
import re
from pathlib import Path
from collections import defaultdict

def extract_rule_names(file_path):
    """Extrait les noms des règles d'un fichier YARA"""
    rules = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Chercher les patterns "rule nom_rule"
            matches = re.finditer(r'^rule\s+(\w+)\s*\{', content, re.MULTILINE)
            for match in matches:
                rules.append(match.group(1))
    except Exception as e:
        print(f"⚠️  Erreur de lecture {file_path}: {e}")
    return rules

def find_duplicate_rules(rules_dir):
    """Trouve tous les doublons de noms de règles"""
    rule_to_files = defaultdict(list)
    
    # Scanner tous les fichiers YARA
    for yara_file in sorted(rules_dir.rglob("*")):
        if yara_file.name in ["index.yar"]:
            continue
        if yara_file.suffix in [".yar", ".yara"]:
            rules = extract_rule_names(yara_file)
            for rule_name in rules:
                rule_to_files[rule_name].append(yara_file)
    
    # Identifier les doublons
    duplicates = {rule: files for rule, files in rule_to_files.items() 
                  if len(files) > 1}
    
    return rule_to_files, duplicates

def rename_duplicates(rules_dir):
    """Renomme les règles dupliquées en ajoutant un suffixe"""
    _, duplicates = find_duplicate_rules(rules_dir)
    
    if not duplicates:
        print("✓ Pas de doublons trouvés!")
        return
    
    print(f"🔍 {len(duplicates)} règles dupliquées détectées:\n")
    
    for rule_name, files in duplicates.items():
        print(f"  • '{rule_name}' trouvée dans {len(files)} fichiers:")
        for i, file_path in enumerate(files):
            print(f"      {i+1}. {file_path.relative_to(rules_dir)}")
    
    print("\n⚠️  Correction des doublons...\n")
    
    # Pour chaque doublon, renommer dans les fichiers secondaires
    for rule_name, files in duplicates.items():
        for idx, file_path in enumerate(files[1:], start=1):  # Skip le premier
            print(f"  📝 Renommage dans {file_path.relative_to(rules_dir)}")
            rename_rule_in_file(file_path, rule_name, f"{rule_name}_{idx}")
            print(f"     '{rule_name}' → '{rule_name}_{idx}'")
    
    print("\n✓ Corrections appliquées!")

def rename_rule_in_file(file_path, old_name, new_name):
    """Renomme une règle dans un fichier YARA"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Remplacer la déclaration de la règle
    new_content = re.sub(
        rf'\brule\s+{re.escape(old_name)}\b',
        f'rule {new_name}',
        content
    )
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

def report_duplicates(rules_dir):
    """Génère un rapport sur les doublons"""
    rule_to_files, duplicates = find_duplicate_rules(rules_dir)
    
    print("=" * 70)
    print("📊 RAPPORT DES RÈGLES YARA")
    print("=" * 70)
    
    print(f"\nTotal de fichiers YARA: {sum(1 for _ in rules_dir.rglob('*') if _.suffix in ['.yar', '.yara'] and _.name != 'index.yar')}")
    print(f"Total de règles: {len(rule_to_files)}")
    print(f"Règles dupliquées: {len(duplicates)}")
    
    if duplicates:
        print("\n⚠️  DOUBLONS:")
        for rule_name, files in sorted(duplicates.items()):
            print(f"\n  {rule_name} ({len(files)} occurrences):")
            for file_path in files:
                print(f"    • {file_path.relative_to(rules_dir)}")
    else:
        print("\n✓ Aucun doublon trouvé")
    
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
        elif cmd == "fix":
            rename_duplicates(rules_dir)
        elif cmd == "check":
            rule_to_files, duplicates = find_duplicate_rules(rules_dir)
            if duplicates:
                print(f"❌ {len(duplicates)} doublons trouvés")
                sys.exit(1)
            else:
                print("✓ Pas de doublons")
                sys.exit(0)
    else:
        print("Usage:")
        print("  python fix_yara_duplicates.py report   - Voir le rapport")
        print("  python fix_yara_duplicates.py check    - Vérifier les doublons")
        print("  python fix_yara_duplicates.py fix      - Corriger les doublons")
        report_duplicates(rules_dir)

if __name__ == "__main__":
    main()
