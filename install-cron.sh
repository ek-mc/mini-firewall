#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$BASE_DIR/ddos-guard.sh"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

chmod +x "$SCRIPT"

# Install dependencies (Debian/Ubuntu best effort)
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y || true
  apt-get install -y ipset iptables iproute2 || true
fi

# Cron every minute
( crontab -l 2>/dev/null | grep -v "ddos-guard.sh"; echo "* * * * * $SCRIPT" ) | crontab -

echo "Installed cron job: * * * * * $SCRIPT"
echo "Done. Check /var/log/ddos-guard.log"
