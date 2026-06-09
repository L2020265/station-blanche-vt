#!/usr/bin/env python3
"""
Génère un index YARA robuste qui gère les doublons automatiquement
- Détecte les noms de règles dupliquées
- Renomme automatiquement les doublons
- Génère un index valide
"""
import re
from pathlib import Path
from collections import defaultdict

def extract_rule_name_and_content(file_path):
    """Extrait les noms et contenus des règles d'un fichier YARA"""
    rules = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Trouver toutes les règles avec leur contenu
            pattern = r'rule\s+(\w+)\s*\{([^}]*\{[^}]*\})*[^}]*\}'
            for match in re.finditer(pattern, content, re.DOTALL):
                rule_name = match.group(1)
                rule_content = match.group(0)
                rules.append({
                    'name': rule_name,
                    'content': rule_content,
                    'start': match.start(),
                    'end': match.end()
                })
    except Exception as e:
        print(f"⚠️  Erreur de lecture {file_path}: {e}")
    return rules

def generate_safe_yara_index(rules_dir):
    """
    Génère un index YARA sûr avec renommage automatique des doublons
    Exclut les index.yar des sous-dossiers pour éviter les conflits
    """
    rules_dir = Path(rules_dir)
    index_file = rules_dir / "index.yar"
    
    # Trouver tous les fichiers YARA (EXCLURE les index.yar dans les sous-dossiers)
    yara_files = []
    for ext in ["*.yar", "*.yara"]:
        for f in sorted(rules_dir.rglob(ext)):
            # Exclure les index.yar (au niveau racine ou sub-dossiers)
            if f.name == "index.yar":
                print(f"⊘ Exclusion: {f.relative_to(rules_dir)} (index local)")
                continue
            yara_files.append(f)
    
    print(f"📝 Génération d'index YARA sûr")
    print(f"   Fichiers trouvés: {len(yara_files)}")
    
    # Extraire tous les noms de règles
    rule_name_to_files = defaultdict(list)
    all_rules = {}
    
    for yara_file in yara_files:
        rules = extract_rule_name_and_content(yara_file)
        for rule in rules:
            rule_name = rule['name']
            rule_name_to_files[rule_name].append(yara_file)
            if rule_name not in all_rules:
                all_rules[rule_name] = (yara_file, rule)
    
    # Identifier les doublons
    duplicates = {name: files for name, files in rule_name_to_files.items() 
                  if len(files) > 1}
    
    if duplicates:
        print(f"\n⚠️  {len(duplicates)} noms de règles dupliquées détectées:")
        for name, files in duplicates.items():
            print(f"   • '{name}' dans {len(files)} fichiers")
            for f in files:
                print(f"      - {f.relative_to(rules_dir)}")
    
    # Construire le contenu de l'index EN MÉMOIRE d'abord
    index_lines = [
        "// Index YARA auto-généré - Ne pas modifier",
        f"// Fichiers inclunis: {len(yara_files)}",
        f"// Noms de règles uniques: {len(all_rules)}",
    ]
    
    if duplicates:
        index_lines.append(f"// ⚠️  {len(duplicates)} noms dupliquées (renommés automatiquement)")
    
    index_lines.append("")
    
    processed_files = set()
    processed_rules = set()
    
    # Traiter chaque fichier YARA
    for yara_file in yara_files:
        relative_path = yara_file.relative_to(rules_dir)
        
        # Lire le fichier
        try:
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read()
        except Exception as e:
            print(f"⚠️  Erreur de lecture {yara_file}: {e}")
            continue
        
        # Extraire les règles et les renommer si nécessaire
        rules = extract_rule_name_and_content(yara_file)
        modified_content = file_content
        
        for rule in rules:
            old_name = rule['name']
            
            # Si c'est un doublon, renommer
            if old_name in duplicates:
                # Créer un nom unique
                file_id = relative_path.stem.replace('.', '_').replace('-', '_')
                new_name = f"{old_name}_{file_id}"
                
                if old_name in processed_rules:
                    new_name = f"{old_name}_{file_id}_{len(processed_rules)}"
                
                print(f"   ✓ Renommage: '{old_name}' → '{new_name}' ({relative_path})")
                
                # Remplacer dans le contenu
                pattern = rf'\brule\s+{re.escape(old_name)}\b'
                modified_content = re.sub(pattern, f'rule {new_name}', modified_content)
                processed_rules.add(old_name)
        
        # Écrire le fichier modifié si des changements ont été faits
        if modified_content != file_content:
            try:
                with open(yara_file, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                print(f"   ✓ Mise à jour: {relative_path}")
            except Exception as e:
                print(f"   ✗ Erreur d'écriture: {e}")
        
        # Ajouter l'include dans l'index (en mémoire)
        index_lines.append(f'include "{relative_path}"')
    
    # ÉCRIRE L'INDEX UNE SEULE FOIS (en dehors de la boucle)
    try:
        with open(index_file, "w", encoding="utf-8") as f:
            f.write("\n".join(index_lines))
        print(f"\n✓ Index créé: {index_file}")
    except Exception as e:
        print(f"✗ Erreur lors de la création de l'index: {e}")
        return None
    
    return index_file

if __name__ == "__main__":
    rules_dir = Path(__file__).parent.parent / "rules"
    generate_safe_yara_index(rules_dir)
