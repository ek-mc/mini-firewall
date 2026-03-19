#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$BASE_DIR/ddos-guard.sh"
WHITELIST_FILE="/etc/ddos-guard/whitelist.txt"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

chmod +x "$SCRIPT"
mkdir -p /etc/ddos-guard /var/lib/ddos-guard
touch "$WHITELIST_FILE"

# Install dependencies (Debian/Ubuntu best effort)
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y || true
  apt-get install -y ipset iptables iproute2 util-linux || true
fi

# Cron every minute
( crontab -l 2>/dev/null | grep -v "ddos-guard.sh"; echo "* * * * * $SCRIPT" ) | crontab -

echo "Installed cron job: * * * * * $SCRIPT"
echo "Whitelist file: $WHITELIST_FILE"
echo "Add trusted IPs one per line to avoid accidental bans."
echo "Done. Check /var/log/ddos-guard.log"
