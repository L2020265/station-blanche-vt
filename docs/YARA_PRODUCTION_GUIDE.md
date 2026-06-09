# Résolution des erreurs YARA en Production

## Problème : "error: duplicated identifier"

Cette erreur apparaît quand :
- Deux règles YARA portent le même nom
- L'index inclut la même règle plusieurs fois
- Des sources GitHub contiennent des règles dupliquées

## Solution : Index YARA Sécurisé

Le nouveau script `generate_safe_yara_index.py` :
- ✅ Détecte les noms de règles dupliquées
- ✅ Les renomme automatiquement de manière unique
- ✅ Génère un index valide sans erreurs
- ✅ Met à jour les fichiers YARA

## Procédure en Production

### Déploiement Initial

```bash
# 1. Télécharger les règles
python scripts/download_yara_rules.py

# 2. Nettoyer les fichiers dupliqués
python scripts/deduplicate_yara.py clean

# 3. Générer l'index sécurisé (renomme les doublons auto)
python scripts/generate_safe_yara_index.py

# 4. Vérifier qu'il n'y a pas d'erreurs YARA
yara -p rules/index.yar /tmp/test_file
```

### Ou tout en une commande

```bash
python scripts/maintain_yara_rules.py
```

## Mode Simulation (sûr)

Avant d'appliquer en production :

```bash
# Voir les fichiers qui seraient supprimés
python scripts/deduplicate_yara.py dry-run

# Voir les renommages qui seraient faits
python scripts/generate_safe_yara_index.py | grep "Renommage"
```

## Structure Finale Attendue

```
rules/
├── index.yar                    # Index généré (inclut tous les fichiers)
├── local/
│   └── suspicious_strings.yar  # Règles personnalisées
└── malware/                     # Téléchargé depuis GitHub
    ├── file1.yar
    └── file2.yar
```

## Exemple de Renommage Automatique

**Avant (erreur) :**
```yara
// malware/file1.yar
rule suspicious_powershell { ... }

// webshells/file1.yar  
rule suspicious_powershell { ... }  ← ERREUR: duplicated identifier
```

**Après (automatique) :**
```yara
// malware/file1.yar
rule suspicious_powershell { ... }

// webshells/file1.yar
rule suspicious_powershell_file1 { ... }  ← Renommé automatiquement
```

## Maintenance Régulière

Mettre à jour mensuellement :

```bash
# Linux/Mac (cron)
0 2 1 * * cd /path/to/app && python scripts/maintain_yara_rules.py

# Windows (Task Scheduler)
# Créer une tâche qui exécute: python scripts/maintain_yara_rules.py
```

## Logs et Débogage

Pour voir les détails du processus :

```bash
python scripts/generate_safe_yara_index.py 2>&1 | tee yara_build.log
```

Le log indiquera :
- ✅ Fichiers traités
- ⚠️ Noms dupliquées détectés
- ✓ Renommages effectués
- Nombre de règles finales

## Rollback en Cas de Problème

Si les règles YARA ne fonctionnent pas :

```bash
# Réinitialiser le dossier rules
rm -rf rules/malware rules/webshells

# Relancer le processus complet
python scripts/maintain_yara_rules.py
```

## Support

Pour déboguer une erreur YARA spécifique :

```bash
# Tester l'index directement
yara -p rules/index.yar /path/to/test/file

# Voir quelle règle pose problème
yara -d rules/index.yar /path/to/test/file 2>&1 | head -20
```
