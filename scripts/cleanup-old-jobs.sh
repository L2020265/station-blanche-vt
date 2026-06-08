#!/usr/bin/env bash
set -euo pipefail
find /srv/station-blanche/jobs -mindepth 1 -maxdepth 1 -type d -mtime +1 -exec rm -rf --one-file-system {} +
find /srv/station-blanche/tmp -mindepth 1 -mtime +1 -exec rm -rf --one-file-system {} +
