#!/usr/bin/env bash
# Run the tests ON THE PI (never on the Mac). Extra args go to pytest.
set -euo pipefail
cd "$(dirname "$0")/.."
rsync -a --delete --exclude __pycache__ travelpi tests travelpi:/tmp/travelpi-test/
ssh travelpi "cd /tmp/travelpi-test && PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider $*"
