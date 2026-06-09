# Règles YARA

Ce dossier contient les règles YARA utilisées pour analyser les fichiers.

## Sources principales

- **Yara-Rules** : Règles communautaires pour malwares
  - URL: `https://github.com/Yara-Rules/rules.git`
  - Fichiers: `*.yar`, `*.yara`

- **ReversingLabs** : Règles pour webshells et malwares
  - URL: `https://github.com/reversinglabs/reversinglabs-yara-rules.git`

- **Malware Hunting** : Règles de chasse aux malwares
  - URL: `https://github.com/0xe4/malware_hunting.git`

## Installation des règles

### Méthode 1 : Automatique

```bash
python scripts/download_yara_rules.py
python scripts/generate_yara_index.py
```

### Méthode 2 : Manuelle

```bash
cd rules

# Cloner les repos
git clone https://github.com/Yara-Rules/rules.git malware
git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git webshells

# Générer l'index
cd ..
python scripts/generate_yara_index.py
```

## Ajouter des règles personnalisées

1. **Créer un fichier YARA** dans `rules/custom/`

```yara
rule suspicious_powershell {
    meta:
        description = "Détecte les scripts PowerShell suspects"
        author = "Votre nom"
        date = "2026-06-09"
    strings:
        $ps1 = "powershell" nocase
        $obfuscated = "FromBase64String" nocase
    condition:
        all of them
}
```

2. **Régénérer l'index** :

```bash
python scripts/generate_yara_index.py
```

## Ajout de sources personnalisées

Modifier `scripts/download_yara_rules.py` et ajouter à `YARA_SOURCES` :

```python
"ma_source": {
    "url": "https://github.com/user/mon-repo.git",
    "path": ".",
    "enabled": True
}
```

## Format d'une règle YARA

```yara
rule nom_descriptif {
    meta:
        description = "Description claire"
        author = "Votre nom"
        date = "YYYY-MM-DD"
        severity = "high"
    
    strings:
        $string1 = "pattern1"
        $string2 = "pattern2" nocase
        $regex = /regex_pattern/ wide
    
    condition:
        1 of them
}
```

## Validation des règles

```bash
# Vérifier la syntaxe d'une règle
yara -p index.yar /chemin/vers/fichier/test

# Tester contre un fichier
yara index.yar /chemin/vers/fichier/a/scanner
```

## Performance

- Les règles complexes ralentissent le scan
- Utilisez `nocase` pour les correspondances insensibles à la casse
- Les regex longues peuvent impacter les performances
- Considérez les conditions avec `1 of them` pour les alternatives

## Licence

Vérifiez la licence de chaque source de règles avant utilisation commerciale.
