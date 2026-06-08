# Recommandations de sécurité

## Durcissement système

- Debian Stable minimal.
- Chiffrement disque LUKS.
- BIOS/UEFI protégé par mot de passe.
- Boot réseau désactivé.
- Services inutiles désactivés.
- nftables en politique deny par défaut.
- USBGuard pour limiter les périphériques USB.

## VirusTotal

- Recherche hash prioritaire.
- Upload complet désactivé par défaut.
- Validation explicite opérateur si upload.
- Ne pas uploader les documents confidentiels.
- Clé API dans `/etc/station-blanche/vt.env`, jamais dans le code.

## Limitations

- Un verdict sain n'est pas une garantie.
- L'analyse est principalement statique.
- Les fichiers chiffrés/protégés peuvent masquer du contenu.
- VirusTotal standard peut partager les fichiers soumis.
