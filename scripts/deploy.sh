#!/usr/bin/env bash
# Copy the app to the Pi and restart it. Usage: scripts/deploy.sh [--setup]  (--setup also runs the one-time network setup)
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/test.sh >/dev/null || { echo "tests failed – not deploying (run scripts/test.sh to see why)"; exit 1; }
rsync -a --delete --rsync-path="sudo rsync" --exclude __pycache__ travelpi deploy travelpi:/opt/travelpi/
# my router's own settings (Tailscale exits, backup server, Sentinel) – kept out of git in local/
[ -f local/settings.json ] && rsync --rsync-path="sudo rsync" --chmod=F644 local/settings.json travelpi:/etc/travelpi/settings.json
if [ "${1:-}" = "--setup" ]; then
  ssh travelpi 'sudo bash /opt/travelpi/deploy/setup-network.sh'
else
  ssh travelpi 'sudo systemctl restart travelpi 2>/dev/null; sleep 2; systemctl is-active travelpi'
fi
