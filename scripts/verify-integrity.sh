#!/usr/bin/env bash
set -euo pipefail
command -v debsums >/dev/null 2>&1 && debsums -s || true
command -v aide >/dev/null 2>&1 && aide --check || true
systemctl status station-blanche-web.service --no-pager || true
