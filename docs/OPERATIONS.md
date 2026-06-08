# Exploitation

## Lancer une analyse

1. Ouvrir `http://127.0.0.1:8080`.
2. Déposer le fichier.
3. Laisser l'upload VirusTotal décoché sauf besoin explicite.
4. Lire le verdict.
5. Télécharger le rapport JSON si nécessaire.

## Journaux

```bash
journalctl -u station-blanche-web.service -f
tail -f /var/log/station-blanche/events.jsonl
ausearch -k station_upload
```

## Nettoyage

```bash
sudo ./scripts/cleanup-old-jobs.sh
```

## Test EICAR

Créer un fichier EICAR uniquement en environnement de test autorisé afin de valider ClamAV.
