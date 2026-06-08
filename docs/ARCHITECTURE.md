# Architecture

## Vue logique

```text
Navigateur local -> FastAPI 127.0.0.1:8080 -> moteur d'analyse
                                      |-> outils locaux : file, ClamAV, YARA, exiftool, strings
                                      |-> VirusTotal : hash lookup puis upload optionnel
```

## Séparation des responsabilités

- `sb-web` : exécute l'interface web.
- `sb-analyzer` : réservé aux traitements d'analyse avancés si séparation renforcée.
- `/srv/station-blanche/jobs` : fichiers temporaires par analyse.
- `/srv/station-blanche/reports` : rapports JSON.
- `/var/log/station-blanche/events.jsonl` : journal applicatif.

## Flux réseau

- Entrant : aucun, sauf loopback local.
- Sortant : uniquement proxy interne.
- Proxy : autorise uniquement VirusTotal en HTTPS.
