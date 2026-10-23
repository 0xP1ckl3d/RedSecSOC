#!/bin/bash
# Install an existing, configured console; does not install or reconfigure Wazuh.
set -euo pipefail
umask 027
cd "$(dirname "$0")/.."
test "$(id -u)" = 0
python3 deploy/install.py
