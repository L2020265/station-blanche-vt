#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "À exécuter en root" >&2
  exit 1
fi

APP_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="/srv/station-blanche"
APP_DST="$BASE/app"

apt update
apt install --no-install-recommends -y \
  python3 python3-venv python3-pip \
  clamav clamav-daemon yara file binutils \
  libimage-exiftool-perl jq auditd usbguard \
  apparmor apparmor-utils bubblewrap \
  nftables rsyslog logrotate curl rsync \
  rkhunter

groupadd --system stationblanche 2>/dev/null || true
useradd --system --home "$BASE" --shell /usr/sbin/nologin --gid stationblanche sb-web 2>/dev/null || true
useradd --system --home "$BASE/analyzer" --shell /usr/sbin/nologin --gid stationblanche sb-analyzer 2>/dev/null || true

mkdir -p "$BASE"/{app,uploads,jobs,reports,quarantine,rules,tmp}
mkdir -p /etc/station-blanche /var/log/station-blanche

rsync -a --delete "$APP_SRC/app/" "$APP_DST/"
rsync -a --delete "$APP_SRC/analyzer/" "$BASE/analyzer/"
rsync -a --delete "$APP_SRC/rules/" "$BASE/rules/"
rsync -a "$APP_SRC/scripts/download_yara_simple.py" "$BASE/scripts/" 2>/dev/null || true

python3 -m venv "$APP_DST/venv"
"$APP_DST/venv/bin/pip" install --upgrade pip
"$APP_DST/venv/bin/pip" install -r "$APP_SRC/requirements.txt"

chown -R root:stationblanche "$BASE"
chown -R sb-web:stationblanche "$BASE/uploads" "$BASE/reports" "$BASE/jobs" "$BASE/tmp"
chown -R sb-analyzer:stationblanche "$BASE/quarantine"
chmod -R 0750 "$BASE"
chmod 0730 "$BASE/uploads"
chmod 0750 /var/log/station-blanche
chown root:stationblanche /var/log/station-blanche

if [[ ! -f /etc/station-blanche/vt.env ]]; then
  install -o root -g sb-web -m 0640 /dev/null /etc/station-blanche/vt.env
  cat >/etc/station-blanche/vt.env <<'EOF'
# Clé API VirusTotal
VT_API_KEY=""

# Upload complet vers VirusTotal : false recommandé par défaut
VT_ENABLE_UPLOAD="false"
VT_MALICIOUS_THRESHOLD="5"
VT_SUSPICIOUS_THRESHOLD="1"

# Proxy recommandé
# HTTPS_PROXY="http://192.168.50.1:3128"
# HTTP_PROXY="http://192.168.50.1:3128"
NO_PROXY="127.0.0.1,localhost"

# Optional: run rkhunter on volume scans if configured in the app.
# SB_RKHUNTER_CMD="rkhunter --check --rwo"
EOF
fi

cp "$APP_SRC/config/systemd/station-blanche-web.service" /etc/systemd/system/station-blanche-web.service
cp "$APP_SRC/config/logrotate/station-blanche" /etc/logrotate.d/station-blanche
cp "$APP_SRC/config/auditd/station-blanche.rules" /etc/audit/rules.d/station-blanche.rules

systemctl daemon-reload
systemctl enable station-blanche-web.service
systemctl enable --now auditd || true
augenrules --load || true

echo "Installation terminée. Configure /etc/station-blanche/vt.env puis lance :"
echo "  systemctl restart station-blanche-web.service"
