# Station Blanche VT — Station blanche Linux à connectivité restreinte

## Objectif

Cette station blanche sert à analyser des fichiers suspects déposés manuellement ou depuis un support USB. Elle réalise :

- des analyses locales : hash, type réel, ClamAV, YARA, métadonnées, chaînes ;
- une recherche VirusTotal par hash ;
- un upload VirusTotal optionnel et explicite si le hash est inconnu ;
- un verdict consolidé : `sain`, `suspect`, `malveillant` ;
- une journalisation JSON locale ;
- un nettoyage automatique des jobs temporaires.

## Modèle réseau

La station n'est pas conçue comme poste Internet. Elle doit être isolée du SI et disposer uniquement d'un flux sortant contrôlé :

```text
Station blanche -> proxy interne -> VirusTotal HTTPS
Tout autre flux entrant/sortant : bloqué
```

Recommandation : utiliser un proxy Squid filtrant par FQDN, et nftables côté station pour n'autoriser que le proxy.

## Avertissement VirusTotal

Le mode recommandé est :

1. calculer le SHA-256 localement ;
2. rechercher le hash dans VirusTotal ;
3. n'uploader le fichier complet que si l'opérateur le valide explicitement.

Ne jamais uploader de fichier interne, personnel, confidentiel ou sensible sans validation RSSI/juridique/métier.

## Arborescence

```text
station-blanche-vt/
├── app/                       # Backend FastAPI + interface web locale
├── analyzer/                  # Moteur d'analyse local + VirusTotal
├── config/                    # systemd, nftables, squid, auditd, logrotate
├── docs/                      # Documentation opérationnelle
├── rules/                     # Règles YARA locales
├── scripts/                   # Installation, maintenance, montage USB
├── tests/                     # Tests simples
├── requirements.txt           # Dépendances Python
└── README.md
```

## Installation rapide

Sur Debian Stable minimal (VM recommandée pour l’isolation) :

```bash
sudo apt update
sudo apt install --no-install-recommends -y \
  python3 python3-venv python3-pip \
  clamav clamav-daemon yara file binutils \
  libimage-exiftool-perl jq auditd usbguard \
  apparmor apparmor-utils bubblewrap \
  nftables rsyslog logrotate curl rsync \
  rkhunter
```

Cette procédure installe tout le nécessaire pour un déploiement Debian/VM. Le script `scripts/install.sh` crée les utilisateurs dédiés, les dossiers, l’environnement Python isolé et l’unité systemd pour le service web.

Puis :

1. (Optionnel mais recommandé) créer et activer un environnement Python isolé :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

2. Lancer le script d'installation qui prépare les chemins, permissions et unités systemd :

```bash
sudo ./scripts/install.sh
```

3. Configurer la clé API VirusTotal et variables d'environnement système :

```bash
sudo mkdir -p /etc/station-blanche
sudo nano /etc/station-blanche/vt.env
```

Exemple minimal (adapter le proxy et la clé) :

```ini
VT_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
VT_ENABLE_UPLOAD="false"
VT_MALICIOUS_THRESHOLD="5"
VT_SUSPICIOUS_THRESHOLD="1"
# Proxy sortant vers votre proxy filtrant (optionnel)
HTTPS_PROXY="http://192.168.50.1:3128"
HTTP_PROXY="http://192.168.50.1:3128"
NO_PROXY="127.0.0.1,localhost"
# Exécuter rkhunter automatiquement pour les scans de volumes (optionnel)
# Exemple: rkhunter --check --rwo
SB_RKHUNTER_CMD="rkhunter --check --rwo"
```

4. Mettre à jour les bases ClamAV et YARA localement (si nécessaire) :

```bash
sudo systemctl stop clamav-freshclam || true
sudo freshclam || true
sudo systemctl start clamav-freshclam || true
```

5. Redémarrer le service web pour prendre en compte la configuration :

```bash
sudo systemctl daemon-reload
sudo systemctl restart station-blanche-web.service
sudo journalctl -u station-blanche-web.service -f
```

6. Vérifier l'accès local depuis la machine :

Ouvrir le navigateur sur `http://127.0.0.1:8080` ou utiliser `curl` :

```bash
curl -sS http://127.0.0.1:8080 | head -n 30
```

Notes opérationnelles :

- Le fichier `vt.env` doit être accessible par l'unité systemd/service (voir `scripts/install.sh`).
- `SB_RKHUNTER_CMD` est facultatif ; si renseigné, l'application lancera la commande une fois par analyse de volume et inclura la sortie dans le rapport groupé.
- L'installation et l'exécution de `rkhunter` peuvent nécessiter des privilèges root pour effectuer des vérifications système. Si vous souhaitez cibler un volume monté (et non le système hôte), utilisez un wrapper sécurisé (bind-mount/chroot) 
- Respectez la politique d'upload VirusTotal : n'activez `VT_ENABLE_UPLOAD` que si la politique interne et la conformité le permettent.

Accès local :

```text
http://127.0.0.1:8080
```

## Installation du filtrage réseau local

Adapter l'IP du proxy dans `config/nftables/station-blanche.nft`, puis :

```bash
sudo cp config/nftables/station-blanche.nft /etc/nftables.conf
sudo systemctl enable --now nftables
sudo nft -f /etc/nftables.conf
```

## Proxy Squid recommandé

Exemple fourni :

```text
config/squid/station-blanche.conf
```

À installer côté proxy, pas sur la station.

## Démarrage / arrêt

```bash
sudo systemctl start station-blanche-web.service
sudo systemctl status station-blanche-web.service
sudo journalctl -u station-blanche-web.service -f
```

## Journalisation

Les rapports sont dans :

```text
/srv/station-blanche/reports/
```

Les événements JSONL sont dans :

```text
/var/log/station-blanche/events.jsonl
```

## Politique de verdict

- `malveillant` : détection ClamAV, règle YARA critique, ou score VirusTotal >= seuil malveillant.
- `suspect` : indicateur faible local, score VirusTotal faible, fichier inconnu VT avec signaux suspects.
- `sain` : aucune alerte détectée.

Un verdict `sain` ne garantit jamais l'absence de menace.

## Mise à jour hors-ligne partielle

Même si VirusTotal est autorisé, les mises à jour OS, YARA et ClamAV doivent idéalement être réalisées via un processus contrôlé :

```bash
sudo ./scripts/import-clamav-db.sh /mnt/maintenance/clamav-db
sudo ./scripts/import-yara-rules.sh /mnt/maintenance/yara-rules
```

## Sécurité opérationnelle

- Ne pas lancer manuellement les fichiers suspects.
- Ne pas ouvrir les documents suspects avec LibreOffice/visionneuse locale.
- Ne pas donner de shell interactif aux comptes `sb-web` ou `sb-analyzer`.
- Ne pas laisser de navigateur Internet généraliste utilisable librement.
- Conserver les rapports, pas les fichiers suspects, sauf besoin d'investigation.


